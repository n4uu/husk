package beacon

import (
	"bytes"
	"encoding/binary"
)

// This file builds synthetic Beacon configs and the minimal PE containers
// to carry them — never used by the decode path, only by tests and the
// `husk fixture` CLI command. It exists so husk's correctness can be
// demonstrated and regression-tested without a real (and, for anyone
// cloning the repo, legally and operationally awkward to obtain) Cobalt
// Strike sample: every value BuildBlob writes, this package can also read
// back.

// Field is one setting to bake into a synthetic config.
type Field struct {
	Index uint16
	Type  Type
	Value []byte // pre-encoded: 2 bytes BE for Short, 4 bytes BE for Int, raw for Str
}

// Short builds a TypeShort field from a plain uint16.
func Short(index uint16, v uint16) Field {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return Field{Index: index, Type: TypeShort, Value: b}
}

// Int builds a TypeInt field from a plain int32.
func Int(index uint16, v int32) Field {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(v))
	return Field{Index: index, Type: TypeInt, Value: b}
}

// Str builds a TypeStr field, right-padded with zero bytes to width (the
// same fixed-width, NUL-padded layout the real generator uses).
func Str(index uint16, s string, width int) Field {
	b := make([]byte, width)
	copy(b, s)
	return Field{Index: index, Type: TypeStr, Value: b}
}

// Raw builds a TypeStr field from an exact byte string with no padding —
// for fields, like the ProcInject transform blobs, that are themselves a
// fully self-describing sub-format.
func Raw(index uint16, b []byte) Field {
	return Field{Index: index, Type: TypeStr, Value: b}
}

// BuildBlob writes fields as a sequential TLV stream — the layout
// ReadEntries expects — zero-padded to size (Cobalt Strike itself pads the
// real config block to a fixed 4096 bytes).
func BuildBlob(fields []Field, size int) []byte {
	var buf bytes.Buffer
	for _, f := range fields {
		header := make([]byte, entryHeaderSize)
		binary.BigEndian.PutUint16(header[0:2], f.Index)
		binary.BigEndian.PutUint16(header[2:4], uint16(f.Type))
		binary.BigEndian.PutUint16(header[4:6], uint16(len(f.Value)))
		buf.Write(header)
		buf.Write(f.Value)
	}

	out := make([]byte, size)
	copy(out, buf.Bytes())
	return out
}

// XOR applies a repeating key (length 1 for the plain single-byte format,
// or 4 for the stageless-encryption outer layer) across data.
func XOR(data []byte, key []byte) []byte {
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ key[i%len(key)]
	}
	return out
}

// ProcInjectTransformBlob builds the wire format decodeProcInjectTransform
// reads: a length-prefixed prepend, then a length-prefixed append.
func ProcInjectTransformBlob(prepend, appendBytes []byte) []byte {
	var buf bytes.Buffer
	writeU32Then(&buf, prepend)
	writeU32Then(&buf, appendBytes)
	return buf.Bytes()
}

func writeU32Then(buf *bytes.Buffer, data []byte) {
	var lenBytes [4]byte
	binary.BigEndian.PutUint32(lenBytes[:], uint32(len(data)))
	buf.Write(lenBytes[:])
	buf.Write(data)
}

// MalleableStreamBlob builds a Malleable_C2_Instructions-style opcode
// stream from step keywords: "remove-end:N", "remove-begin:N", or a bare
// opcode name from malleableOps (e.g. "base64 decode").
func MalleableStreamBlob(steps ...string) []byte {
	var buf bytes.Buffer
	for _, step := range steps {
		writeMalleableStep(&buf, step)
	}
	writeU32(&buf, 0) // terminator
	return buf.Bytes()
}

func writeMalleableStep(buf *bytes.Buffer, step string) {
	switch {
	case hasPrefix(step, "remove-end:"):
		writeU32(buf, 1)
		writeU32(buf, parseUint(step[len("remove-end:"):]))
	case hasPrefix(step, "remove-begin:"):
		writeU32(buf, 2)
		writeU32(buf, parseUint(step[len("remove-begin:"):]))
	default:
		for op, name := range malleableOps {
			if name == step {
				writeU32(buf, op)
				return
			}
		}
	}
}

func writeU32(buf *bytes.Buffer, v uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	buf.Write(b[:])
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func parseUint(s string) uint32 {
	var v uint32
	for _, r := range s {
		if r < '0' || r > '9' {
			break
		}
		v = v*10 + uint32(r-'0')
	}
	return v
}
