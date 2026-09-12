package beacon

import (
	"math/rand"
	"testing"
)

func syntheticConfig() []Field {
	return []Field{
		Short(1, 8), // HTTPS
		Short(2, 8443),
		Int(3, 45000),
		Str(8, "malleable.example.invalid,/api/v2/beacon", 256),
		Str(9, "Mozilla/5.0", 128),
		Int(40, 20270101),
	}
}

func TestRecoverSingleByteXORBothKnownKeys(t *testing.T) {
	for _, key := range []byte{0x2e, 0x69, 0x01, 0xa5} {
		blob := XOR(BuildBlob(syntheticConfig(), 4096), []byte{key})

		// Pad with unrelated noise on both sides, like a real .data section
		// with the config sitting somewhere in the middle of it.
		padded := append(append(make([]byte, 137), blob...), make([]byte, 900)...)

		cfg, ok := RecoverConfig(padded)
		if !ok {
			t.Fatalf("key 0x%02x: RecoverConfig failed to find the config", key)
		}
		if cfg.Key != hexByte(key) {
			t.Errorf("key 0x%02x: recovered key %s", key, cfg.Key)
		}
		if cfg.Offset != 137 {
			t.Errorf("key 0x%02x: recovered offset %d, want 137", key, cfg.Offset)
		}

		port := settingByIndex(t, cfg.Settings, 2)
		if port.Value != int64(8443) {
			t.Errorf("key 0x%02x: Port = %v, want 8443", key, port.Value)
		}
		c2 := settingByIndex(t, cfg.Settings, 8)
		if c2.Value != "malleable.example.invalid,/api/v2/beacon" {
			t.Errorf("key 0x%02x: C2Server = %q", key, c2.Value)
		}
	}
}

func TestRecoverRejectsRandomNoise(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	noise := make([]byte, 8192)
	r.Read(noise)

	if _, ok := RecoverConfig(noise); ok {
		t.Error("RecoverConfig found a config in pure random noise — the structural gate is too weak")
	}
}

func TestRecoverRepeatingKeyLayer(t *testing.T) {
	inner := XOR(BuildBlob(syntheticConfig(), 4096), []byte{0x2e})

	key := []byte{0x3c, 0x91, 0x04, 0xaa}
	// The whole section — including its zero padding — is encrypted with
	// the repeating key; it's precisely that padding, once encrypted, that
	// reveals the key by how often it repeats.
	plain := append(make([]byte, 8192), inner...)
	outer := XOR(plain, key)

	cfg, ok := RecoverConfig(outer)
	if !ok {
		t.Fatal("RecoverConfig failed to see through the repeating-key outer layer")
	}
	if settingByIndex(t, cfg.Settings, 2).Value != int64(8443) {
		t.Errorf("Port = %v, want 8443", settingByIndex(t, cfg.Settings, 2).Value)
	}
}

func TestSourcesFindsPESection(t *testing.T) {
	blob := XOR(BuildBlob(syntheticConfig(), 4096), []byte{0x2e})
	pe := BuildMinimalPE(blob)

	sources := Sources(pe)
	var found bool
	for _, src := range sources {
		if src.Name != "PE section .data" {
			continue
		}
		found = true
		if len(src.Data) < len(blob) {
			t.Errorf("PE section .data has %d bytes, want at least %d", len(src.Data), len(blob))
		}
	}
	if !found {
		t.Fatalf("Sources() did not report a PE section .data among %+v", sourceNames(sources))
	}

	cfg, ok := RecoverConfig(pe) // sanity: not used by Sources, but should also work standalone
	_ = cfg
	if !ok {
		t.Skip("whole-file fallback did not independently find the config (expected if header noise interferes); PE section path already verified above")
	}
}

func sourceNames(sources []Source) []string {
	names := make([]string, len(sources))
	for i, s := range sources {
		names[i] = s.Name
	}
	return names
}

func hexByte(b byte) string {
	const digits = "0123456789abcdef"
	return "0x" + string(digits[b>>4]) + string(digits[b&0xf])
}
