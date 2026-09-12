package beacon

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
)

// This file decodes the three distinct little sub-languages Cobalt Strike
// compiles a Malleable C2 profile into and bakes straight into the Beacon
// binary. They're easy to mix up — all three are opcode streams read from a
// blob-typed setting — so each gets its own decoder rather than one
// generic "transform" path:
//
//   - ProcInject_PrependAppend_x86/x64 (46/47): not really an opcode stream
//     at all, just two length-prefixed byte strings glued around injected
//     shellcode, most often to break naive signature scans of the injected
//     region.
//   - Malleable_C2_Instructions (11): how the beacon transforms the raw
//     bytes it gets back from the C2 server before treating them as tasking
//     — e.g. "strip N bytes off the front, then base64-decode".
//   - HttpGet_Metadata / HttpPost_Metadata (12/13): the richer instruction
//     set for how the beacon's *outbound* session id and task output get
//     smuggled into headers, URI segments, or POST parameters.

// decodeProcInjectTransform reads the 46/47 wire layout: a big-endian
// uint32 prepend length, that many prepend bytes, a big-endian uint32
// append length, and that many append bytes. An all-zero blob, or an append
// half that is itself all zero, means that half of the profile isn't set.
func decodeProcInjectTransform(raw []byte) ProcInjectTransformValue {
	if isAllZero(raw) {
		return ProcInjectTransformValue{}
	}

	var v ProcInjectTransformValue

	prependLen, rest, ok := readU32BE(raw, 0)
	if !ok {
		return v
	}
	prepend, ok := readN(rest, 0, int(prependLen))
	if ok && !isAllZero(prepend) {
		v.Prepend = hex.EncodeToString(prepend)
	}

	appendOffset := 4 + int(prependLen)
	appendLen, rest2, ok := readU32BE(raw, appendOffset)
	if !ok {
		return v
	}
	appendData, ok := readN(rest2, 0, int(appendLen))
	if ok && appendLen < 256 && !isAllZero(appendData) {
		v.Append = hex.EncodeToString(appendData)
	}

	return v
}

// malleableOps are Malleable_C2_Instructions' opcodes: how the beacon
// unwraps a server response before treating it as tasking.
var malleableOps = map[uint32]string{
	3:  "base64 decode",
	8:  "NetBIOS decode 'a'",
	11: "NetBIOS decode 'A'",
	13: "base64 URL-safe decode",
	15: "XOR mask w/ random key",
}

// decodeMalleableStream reads a stream of big-endian uint32 opcodes,
// stopping at a 0 opcode, truncated input, or (deliberately, unlike the
// steps below) any opcode this decoder doesn't recognize — an unbounded
// blob under attacker control should never be able to spin this loop
// forever.
func decodeMalleableStream(raw []byte) []string {
	r := bytes.NewReader(raw)
	var steps []string

	for {
		op, ok := readU32(r)
		if !ok || op == 0 {
			break
		}

		switch op {
		case 1, 2:
			n, ok := readU32(r)
			if !ok {
				return steps
			}
			verb := "Remove %d bytes from the end"
			if op == 2 {
				verb = "Remove %d bytes from the beginning"
			}
			steps = append(steps, fmt.Sprintf(verb, n))
		default:
			name, known := malleableOps[op]
			if !known {
				return steps
			}
			steps = append(steps, name)
		}
	}

	return steps
}

// headerTransformOps names every opcode HttpGet_Metadata / HttpPost_Metadata
// can carry — Cobalt Strike's own vocabulary for a Malleable C2 profile's
// client { metadata / output } blocks compiled to bytecode.
var headerTransformOps = map[uint32]string{
	3: "base64", 4: "print", 8: "netbios", 11: "netbiosu",
	12: "uri_append", 13: "base64url", 15: "mask",
}

// decodeHeaderTransform reads the richer opcode stream behind
// HttpGet_Metadata (index 12) and HttpPost_Metadata (index 13). Opcode 7
// ("build") switches which output bucket subsequent steps land in: index 12
// always feeds Metadata, while on index 13 a build with a zero name selects
// SessionId and any other name selects Output. Opcode 14 ("strrep") isn't
// handled — matching the reference implementation, which also stops there —
// so a profile step that uses it truncates the decoded chain at that point
// rather than misinterpreting the bytes that follow.
func decodeHeaderTransform(index int, raw []byte) HeaderTransformValue {
	r := bytes.NewReader(raw)
	var v HeaderTransformValue
	category := "" // no bucket selected yet; only build() picks one

	appendTo := func(dst *[]string, s string) {
		if dst != nil {
			*dst = append(*dst, s)
		}
	}
	bucket := func() *[]string {
		switch category {
		case "Metadata":
			return &v.Metadata
		case "SessionId":
			return &v.SessionID
		case "Output":
			return &v.Output
		default:
			return nil
		}
	}

	for {
		op, ok := readU32(r)
		if !ok || op == 0 {
			break
		}

		switch {
		case op == 7:
			name, ok := readU32(r)
			if !ok {
				return v
			}
			if index == 12 {
				category = "Metadata"
			} else if name == 0 {
				category = "SessionId"
			} else {
				category = "Output"
			}

		case op == 1 || op == 2 || op == 5 || op == 6:
			data, ok := readLengthPrefixed(r)
			if !ok {
				return v
			}
			name := map[uint32]string{1: "append", 2: "prepend", 5: "parameter", 6: "header"}[op]
			appendTo(bucket(), fmt.Sprintf("%s %q", name, string(data)))

		case op == 9 || op == 10 || op == 16:
			data, ok := readLengthPrefixed(r)
			if !ok {
				return v
			}
			if op == 9 {
				v.ConstParams = append(v.ConstParams, string(data))
			} else {
				v.ConstHeaders = append(v.ConstHeaders, string(data))
			}

		default:
			if name, known := headerTransformOps[op]; known {
				appendTo(bucket(), name)
				continue
			}
			return v // includes opcode 14 (strrep) and anything unrecognized
		}
	}

	return v
}

// decodeExecuteChain reads ProcInject_Execute (index 51): a sequence of
// single-byte technique IDs from the executeType table, terminated by a
// zero byte. A byte that isn't in the table marks a "custom" technique
// instead of ending the chain — three bytes are skipped (an internal marker
// this decoder doesn't need), then two length-prefixed strings follow
// (module and function name for an indirect syscall-style technique),
// rendered as "module:function".
func decodeExecuteChain(raw []byte) []string {
	var steps []string

	i := 0
	for i < len(raw) {
		v := raw[i]
		if v == 0 {
			break
		}

		if name, known := executeType[int64(v)]; known {
			steps = append(steps, name)
			i++
			continue
		}

		mod, modEnd, ok := readLengthPrefixedAt(raw, i+3)
		if !ok {
			break
		}
		fn, fnEnd, ok := readLengthPrefixedAt(raw, modEnd)
		if !ok {
			break
		}
		steps = append(steps, fmt.Sprintf("%s:%s", trimmedString(mod), trimmedString(fn)))
		i = fnEnd
	}

	return steps
}

func isAllZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func readU32(r *bytes.Reader) (uint32, bool) {
	var v uint32
	if err := binary.Read(r, binary.BigEndian, &v); err != nil {
		return 0, false
	}
	return v, true
}

func readU32BE(buf []byte, offset int) (uint32, []byte, bool) {
	if offset+4 > len(buf) {
		return 0, nil, false
	}
	return binary.BigEndian.Uint32(buf[offset : offset+4]), buf[offset+4:], true
}

func readN(buf []byte, offset, n int) ([]byte, bool) {
	if n < 0 || offset+n > len(buf) {
		return nil, false
	}
	return buf[offset : offset+n], true
}

func readLengthPrefixed(r *bytes.Reader) ([]byte, bool) {
	n, ok := readU32(r)
	if !ok {
		return nil, false
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, false
	}
	return buf, true
}

// readLengthPrefixedAt reads a uint32-BE-length-prefixed byte string at a
// fixed offset and returns the offset just past it, for decoders that walk
// a byte slice by index rather than through an io.Reader.
func readLengthPrefixedAt(buf []byte, offset int) (data []byte, next int, ok bool) {
	length, rest, ok := readU32BE(buf, offset)
	if !ok {
		return nil, 0, false
	}
	data, ok = readN(rest, 0, int(length))
	if !ok {
		return nil, 0, false
	}
	return data, offset + 4 + int(length), true
}
