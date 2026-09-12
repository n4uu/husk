package beacon

import (
	"reflect"
	"testing"
)

func settingByIndex(t *testing.T, settings []Setting, index int) Setting {
	t.Helper()
	for _, s := range settings {
		if s.Index == index {
			return s
		}
	}
	t.Fatalf("no setting with index %d in %+v", index, settings)
	return Setting{}
}

func decodeFields(t *testing.T, fields ...Field) []Setting {
	t.Helper()
	blob := BuildBlob(fields, 512)
	entries := ReadEntries(blob)
	if len(entries) != len(fields) {
		t.Fatalf("ReadEntries returned %d entries, want %d", len(entries), len(fields))
	}
	return Decode(entries)
}

func TestReadEntriesStopsAtZeroPadding(t *testing.T) {
	blob := BuildBlob([]Field{Short(2, 443), Int(3, 60000)}, 4096)
	entries := ReadEntries(blob)
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2 (padding must not be read as a 3rd entry)", len(entries))
	}
}

func TestReadEntriesRejectsBadFixedWidth(t *testing.T) {
	// A TypeShort header claiming a length other than 2 isn't a real short
	// value, so ReadEntries must stop rather than misread the stream.
	blob := []byte{0, 2, 0, 1, 0, 4, 0, 0, 0, 0}
	if entries := ReadEntries(blob); len(entries) != 0 {
		t.Fatalf("got %d entries from a malformed width header, want 0", len(entries))
	}
}

func TestReadEntriesBoundsSafety(t *testing.T) {
	// A length that would run past the buffer must stop the walk, not panic
	// or read out of bounds; this is attacker-controlled input.
	blob := []byte{0, 8, 0, 3, 0xff, 0xff, 'x'}
	if entries := ReadEntries(blob); len(entries) != 0 {
		t.Fatalf("got %d entries from a truncated value, want 0", len(entries))
	}
}

func TestDecodePlainTypes(t *testing.T) {
	settings := decodeFields(t, Short(2, 8080), Int(3, 90000), Str(9, "curl/8.0", 32))

	if v := settingByIndex(t, settings, 2).Value; v != int64(8080) {
		t.Errorf("Port = %v, want 8080", v)
	}
	if v := settingByIndex(t, settings, 3).Value; v != int64(90000) {
		t.Errorf("SleepTime = %v, want 90000", v)
	}
	if v := settingByIndex(t, settings, 9).Value; v != "curl/8.0" {
		t.Errorf("UserAgent = %q, want curl/8.0 (NUL padding must be trimmed)", v)
	}
}

func TestDecodeUnknownIndexIsSurfaced(t *testing.T) {
	settings := decodeFields(t, Short(200, 42))
	s := settingByIndex(t, settings, 200)
	if s.Name != "unknown_200" {
		t.Errorf("Name = %q, want unknown_200", s.Name)
	}
	if s.Value != int64(42) {
		t.Errorf("Value = %v, want 42 (an unrecognized index should still decode by its wire type)", s.Value)
	}
}

func TestDecodeBoolWithFalseValue(t *testing.T) {
	cases := []struct {
		encoded uint16
		want    bool
	}{{4, false}, {1, true}, {0, true}}
	for _, c := range cases {
		settings := decodeFields(t, Short(43, c.encoded)) // bProcInject_StartRWX, falseValue=4
		if got := settingByIndex(t, settings, 43).Value; got != c.want {
			t.Errorf("bProcInject_StartRWX(%d) = %v, want %v", c.encoded, got, c.want)
		}
	}
}

func TestDecodeBeaconTypeMask(t *testing.T) {
	settings := decodeFields(t, Short(1, 0x8)) // HTTPS
	got := settingByIndex(t, settings, 1).Value
	want := []string{"HTTPS"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("BeaconType = %v, want %v", got, want)
	}
}

func TestDecodeIPv4(t *testing.T) {
	ip := uint32(0xC0A80001) // 192.168.0.1
	settings := decodeFields(t, Int(19, int32(ip)))
	if got := settingByIndex(t, settings, 19).Value; got != "192.168.0.1" {
		t.Errorf("DNS_Idle = %v, want 192.168.0.1", got)
	}
}

func TestDecodeKillDate(t *testing.T) {
	settings := decodeFields(t, Int(40, 20261231))
	if got := settingByIndex(t, settings, 40).Value; got != "2026-12-31" {
		t.Errorf("KillDate = %v, want 2026-12-31", got)
	}

	settings = decodeFields(t, Int(40, 0))
	if got := settingByIndex(t, settings, 40).Value; got != "" {
		t.Errorf("KillDate(0) = %v, want empty (unset)", got)
	}
}

func TestDecodePublicKey(t *testing.T) {
	key := make([]byte, 256)
	for i := range key {
		key[i] = byte(i)
	}
	settings := decodeFields(t, Raw(7, key))
	got, ok := settingByIndex(t, settings, 7).Value.(PublicKeyValue)
	if !ok {
		t.Fatalf("PublicKey value has type %T, want PublicKeyValue", settingByIndex(t, settings, 7).Value)
	}
	if len(got.Hex) != 512 || len(got.MD5) != 32 {
		t.Errorf("PublicKey = %+v, want 512 hex chars and a 32-char md5", got)
	}
}

func TestDecodeProcInjectTransform(t *testing.T) {
	blob := ProcInjectTransformBlob([]byte{0x90, 0x90}, []byte{0xCC})
	settings := decodeFields(t, Raw(46, blob))
	got, ok := settingByIndex(t, settings, 46).Value.(ProcInjectTransformValue)
	if !ok || got.Prepend != "9090" || got.Append != "cc" {
		t.Errorf("ProcInject_PrependAppend_x86 = %+v, want prepend=9090 append=cc", got)
	}
}

func TestDecodeProcInjectTransformEmpty(t *testing.T) {
	blob := make([]byte, 8)
	settings := decodeFields(t, Raw(46, blob))
	got := settingByIndex(t, settings, 46).Value.(ProcInjectTransformValue)
	if !got.empty() {
		t.Errorf("ProcInject_PrependAppend_x86 = %+v, want empty for an all-zero blob", got)
	}
}

func TestDecodeMalleableStream(t *testing.T) {
	blob := MalleableStreamBlob("remove-begin:4", "base64 decode", "NetBIOS decode 'a'")
	settings := decodeFields(t, Raw(11, blob))
	want := []string{"Remove 4 bytes from the beginning", "base64 decode", "NetBIOS decode 'a'"}
	if got := settingByIndex(t, settings, 11).Value; !reflect.DeepEqual(got, want) {
		t.Errorf("Malleable_C2_Instructions = %v, want %v", got, want)
	}
}

func TestDecodeExecuteChain(t *testing.T) {
	settings := decodeFields(t, Raw(51, []byte{3, 4, 0})) // CreateRemoteThread, RtlCreateUserThread, stop
	want := []string{"CreateRemoteThread", "RtlCreateUserThread"}
	if got := settingByIndex(t, settings, 51).Value; !reflect.DeepEqual(got, want) {
		t.Errorf("ProcInject_Execute = %v, want %v", got, want)
	}
}

func TestDecodeHeaderTransformGet(t *testing.T) {
	var buf []byte
	writeU32 := func(v uint32) {
		b := make([]byte, 4)
		putU32(b, v)
		buf = append(buf, b...)
	}
	writeBuild := func(name uint32) { writeU32(7); writeU32(name) }
	writeLenPrefixed := func(op uint32, data []byte) {
		writeU32(op)
		writeU32(uint32(len(data)))
		buf = append(buf, data...)
	}
	writeBare := func(op uint32) { writeU32(op) }

	writeBuild(0) // -> Metadata on index 12, regardless of name
	writeLenPrefixed(6, []byte("X-Session"))
	writeBare(3) // base64
	writeU32(0)  // terminator

	settings := decodeFields(t, Raw(12, buf))
	got := settingByIndex(t, settings, 12).Value.(HeaderTransformValue)
	want := []string{`header "X-Session"`, "base64"}
	if !reflect.DeepEqual(got.Metadata, want) {
		t.Errorf("HttpGet_Metadata.Metadata = %v, want %v", got.Metadata, want)
	}
}

func putU32(b []byte, v uint32) {
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}
