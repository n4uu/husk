package beacon

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// maxEntries bounds a single decode pass: real configs carry at most 73
// settings, so this is generous headroom against a corrupt or adversarial
// blob turning a parse into an unbounded loop.
const maxEntries = 256

// ReadEntries walks buf as a sequential stream of TLV records: a 6-byte
// [index][type][length] header (three big-endian uint16 fields), followed by
// length bytes of value. It stops at the first all-zero header, a type
// outside {short,int,str}, or a length that would run past the buffer.
//
// This is a deliberate departure from the reference implementation's
// approach, which searches the blob for each known setting's own header
// bytes and, for string settings, retries with doubling guessed lengths
// until a match turns up (the length isn't otherwise available to it). Here
// the length is read directly from the entry that's actually being decoded,
// so no guessing is needed. As a side effect, ReadEntries surfaces
// every entry in the blob, including setting indices this package's catalog
// doesn't know about yet (a newer Beacon version, a custom build), as
// unrecognized rather than silently dropping them.
func ReadEntries(buf []byte) []Entry {
	var entries []Entry

	offset := 0
	for len(entries) < maxEntries {
		if offset+entryHeaderSize > len(buf) {
			break
		}

		index := binary.BigEndian.Uint16(buf[offset : offset+2])
		typ := Type(binary.BigEndian.Uint16(buf[offset+2 : offset+4]))
		length := binary.BigEndian.Uint16(buf[offset+4 : offset+6])

		if index == 0 && typ == TypeNone && length == 0 {
			break // padding: the generator zero-fills the rest of the block
		}
		if typ != TypeShort && typ != TypeInt && typ != TypeStr {
			break // not a header we understand, so this is the end of the real entries
		}
		if (typ == TypeShort && length != 2) || (typ == TypeInt && length != 4) {
			break // a fixed-width type with the wrong width isn't real data
		}

		start := offset + entryHeaderSize
		end := start + int(length)
		if end > len(buf) {
			break
		}

		entries = append(entries, Entry{Index: index, Type: typ, Length: length, Value: buf[start:end]})
		offset = end
	}

	return entries
}

// Decode turns raw TLV entries into catalog-resolved Settings. Entries whose
// index appears more than once (PublicKey's raw blob and the beacon's own
// separate settings both live at some indices in the wire format) are kept
// in encounter order rather than deduplicated, since which one is
// "authoritative" isn't something husk can know in general.
func Decode(entries []Entry) []Setting {
	settings := make([]Setting, 0, len(entries))
	for _, e := range entries {
		settings = append(settings, decodeOne(e))
	}
	return settings
}

func decodeOne(e Entry) Setting {
	d, known := catalog[int(e.Index)]
	s := Setting{Index: int(e.Index), Type: e.Type, Raw: e.Value}
	if known {
		s.Name = d.name
	} else {
		s.Name = fmt.Sprintf("unknown_%d", e.Index)
	}

	switch {
	case !known:
		s.Value = plainValue(e)
	case d.kind == kindBool:
		s.Value = numericValue(e) != d.falseValue
	case d.kind == kindIPv4:
		s.Value = ipv4Value(e)
	case d.kind == kindKillDate:
		s.Value = killDateValue(e)
	case d.kind == kindHex:
		s.Value = hex.EncodeToString(trimTrailingZero(e.Value))
	case d.kind == kindEnum:
		v := numericValue(e)
		if d.enumFn != nil {
			s.Value = d.enumFn(v)
		} else {
			s.Value = enumLookup(d.enum, v)
		}
	case d.kind == kindMask:
		s.Value = beaconTypeFlags(numericValue(e))
	case d.kind == kindPublicKey:
		s.Value = decodePublicKey(e.Value)
	case d.kind == kindProcInject:
		s.Value = decodeProcInjectTransform(e.Value)
	case d.kind == kindMalleableStream:
		s.Value = decodeMalleableStream(e.Value)
	case d.kind == kindHeaderTransform:
		s.Value = decodeHeaderTransform(int(e.Index), e.Value)
	case d.kind == kindExecuteChain:
		s.Value = decodeExecuteChain(e.Value)
	default:
		s.Value = plainValue(e)
	}

	return s
}

func plainValue(e Entry) any {
	switch e.Type {
	case TypeShort, TypeInt:
		return numericValue(e)
	default:
		return trimmedString(e.Value)
	}
}

func numericValue(e Entry) int64 {
	switch e.Type {
	case TypeShort:
		if len(e.Value) < 2 {
			return 0
		}
		return int64(binary.BigEndian.Uint16(e.Value))
	case TypeInt:
		if len(e.Value) < 4 {
			return 0
		}
		return int64(int32(binary.BigEndian.Uint32(e.Value)))
	default:
		return 0
	}
}

func ipv4Value(e Entry) string {
	if len(e.Value) < 4 {
		return ""
	}
	b := e.Value
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}

func killDateValue(e Entry) string {
	v := numericValue(e)
	if v == 0 {
		return ""
	}
	s := fmt.Sprintf("%08d", v)
	return fmt.Sprintf("%s-%s-%s", s[0:4], s[4:6], s[6:8])
}

func decodePublicKey(raw []byte) PublicKeyValue {
	sum := md5.Sum(raw)
	return PublicKeyValue{Hex: hex.EncodeToString(raw), MD5: hex.EncodeToString(sum[:])}
}

// trimTrailingZero strips the NUL padding a fixed-length blob field is
// padded out to, without disturbing any NUL bytes that are genuinely part
// of the payload before that padding starts.
func trimTrailingZero(b []byte) []byte {
	end := len(b)
	for end > 0 && b[end-1] == 0 {
		end--
	}
	return b[:end]
}

func trimmedString(b []byte) string {
	return string(trimTrailingZero(b))
}
