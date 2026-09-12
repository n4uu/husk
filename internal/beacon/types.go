// Package beacon decodes Cobalt Strike Beacon's binary configuration block:
// the single-byte XOR-obfuscated, type-length-value structure every Beacon
// payload carries its C2 profile, sleep timers, and process-injection
// parameters in.
//
// This is a from-scratch, clean-room implementation, written against the
// wire format as documented publicly and cross-checked line-by-line against
// SentinelOne's reference parser (see README.md for citations) — no code
// from that or any other parser was copied. It exists for defensive
// tooling: pulling C2 infrastructure and behavior out of an implant found
// during incident response, before it goes into a blocklist or a report.
package beacon

import "fmt"

// Type is the wire type tag of a decoded setting's value.
type Type uint16

const (
	TypeNone  Type = 0
	TypeShort Type = 1 // big-endian uint16
	TypeInt   Type = 2 // big-endian uint32
	TypeStr   Type = 3 // raw bytes, meaning depends on the setting
)

func (t Type) String() string {
	switch t {
	case TypeShort:
		return "short"
	case TypeInt:
		return "int"
	case TypeStr:
		return "str"
	default:
		return fmt.Sprintf("unknown(%d)", uint16(t))
	}
}

// entryHeaderSize: three big-endian uint16 fields — index, type, length —
// ahead of every entry's value. The high byte of the index field is always
// zero in every observed build (indices top out at 73), but the field is a
// full uint16 in the wire format.
const entryHeaderSize = 6

// Entry is one raw TLV record exactly as it appears in the decoded config
// block, before any per-setting interpretation.
type Entry struct {
	Index  uint16
	Type   Type
	Length uint16
	Value  []byte
}

// Setting is an Entry after being matched against the known catalog and
// rendered into a human- and JSON-meaningful value.
type Setting struct {
	Index int
	Name  string // "unknown_N" if Index isn't in the catalog
	Type  Type
	Raw   []byte
	Value any
}

// PublicKeyValue is Setting.Value for the PublicKey entry (index 7). The MD5
// of the raw key blob is included because it's a well-known correlation
// pivot: threat intel reporting on Cobalt Strike infrastructure often
// clusters otherwise-unrelated C2 servers by a shared beacon public key
// hash, since operators frequently reuse one Cobalt Strike license/key pair
// across many campaigns.
type PublicKeyValue struct {
	Hex string `json:"hex"`
	MD5 string `json:"md5"`
}

// ProcInjectTransformValue is Setting.Value for ProcInject_PrependAppend_x86
// /x64 (indices 46/47): raw byte strings stitched around injected shellcode,
// commonly used to defeat naive signature scanning of the injected region.
type ProcInjectTransformValue struct {
	Prepend string `json:"prepend_hex,omitempty"`
	Append  string `json:"append_hex,omitempty"`
}

func (v ProcInjectTransformValue) empty() bool {
	return v.Prepend == "" && v.Append == ""
}

// HeaderTransformValue is Setting.Value for HttpGet_Metadata /
// HttpPost_Metadata (indices 12/13): the compiled Malleable C2 instruction
// chain describing how the beacon smuggles its session id and task output
// into HTTP headers, URI segments, or POST bodies.
type HeaderTransformValue struct {
	ConstHeaders []string `json:"const_headers,omitempty"`
	ConstParams  []string `json:"const_params,omitempty"`
	Metadata     []string `json:"metadata,omitempty"`
	SessionID    []string `json:"session_id,omitempty"`
	Output       []string `json:"output,omitempty"`
}

func (v HeaderTransformValue) empty() bool {
	return len(v.ConstHeaders) == 0 && len(v.ConstParams) == 0 &&
		len(v.Metadata) == 0 && len(v.SessionID) == 0 && len(v.Output) == 0
}
