package beacon

import (
	"encoding/hex"
	"fmt"
)

// Config is a located and decoded Beacon configuration block.
type Config struct {
	// Offset is where the encoded block starts within the buffer that was
	// actually searched (see RecoverConfig's two-stage note below).
	Offset int
	// Key is a short human description of the recovered key, e.g. "0x2e"
	// for a single byte or "3c 91 04 aa" for a 4-byte repeating key.
	Key      string
	Entries  []Entry
	Settings []Setting
}

const (
	// minEntries/minKnown gate how many consecutive, structurally valid TLV
	// entries — and how many of those matching a real catalog index — a
	// candidate (offset, key) pair needs before it's accepted. A random
	// 6-byte sequence occasionally looks like a valid header by chance;
	// chaining several in a row *and* having most of them name a real
	// setting is not something noise does convincingly.
	minEntries = 5
	minKnown   = 3

	// maxScanBytes bounds the brute-force search so a large input (a full
	// memory dump handed in by mistake, say) can't turn a single run into a
	// multi-minute scan. A Beacon's encoded config block is a few KB at
	// most and typically sits early in its .data section, so this is
	// generous headroom, not a tight fit.
	maxScanBytes = 4 << 20 // 4 MiB

	// repeatingKeyThreshold: how many times a candidate 4-byte value must
	// repeat before it's trusted as a stageless beacon's whole-section XOR
	// key. Large stretches of an unpacked beacon image are zero-padding,
	// which XORs to the key itself — real keys clear this bar by a wide
	// margin, and stray coincidences don't.
	repeatingKeyThreshold = 1024
)

// RecoverConfig locates and decodes a Beacon config in data, which may be a
// whole PE, a section dump, a raw shellcode blob, or a memory dump — a two
// stage search:
//
//  1. Look for the plain form directly: a run of TLV entries revealed by
//     XOR-ing with some single byte.
//  2. If that fails, data may be a stageless beacon whose entire image is
//     wrapped in a second, outer layer — a repeating 4-byte key applied
//     across a whole PE section. Recover that key, strip the layer, and
//     retry step 1 against what's underneath.
func RecoverConfig(data []byte) (*Config, bool) {
	if cfg, ok := findSingleByteXOR(data); ok {
		return cfg, true
	}

	if inner, ok := findRepeatingKeyLayer(data); ok {
		if cfg, ok := findSingleByteXOR(inner); ok {
			return cfg, true
		}
	}

	return nil, false
}

// findSingleByteXOR brute-forces every one of the 256 possible single-byte
// keys and every candidate start offset, decoding each and keeping whatever
// scores highest against the structural gate above. This subsumes the two
// keys actually observed in the wild (0x69 for Beacon 3, 0x2e for Beacon 4)
// without hardcoding either — a differently-keyed build, if one ever
// existed, would still be found.
func findSingleByteXOR(data []byte) (*Config, bool) {
	scanLen := len(data)
	if scanLen > maxScanBytes {
		scanLen = maxScanBytes
	}

	var best *Config
	bestScore := 0

	buf := make([]byte, scanLen)
	for key := 0; key < 256; key++ {
		k := byte(key)
		for i, b := range data[:scanLen] {
			buf[i] = b ^ k
		}

		for offset := 0; offset+entryHeaderSize <= scanLen; offset++ {
			entries := ReadEntries(buf[offset:])
			if len(entries) < minEntries {
				continue
			}
			known := countKnown(entries)
			if known < minKnown {
				continue
			}
			if score := len(entries) + known; score > bestScore {
				bestScore = score
				// buf is reused (and mutated) for every remaining candidate
				// key, so entries' Value slices — which alias it — must be
				// deep-copied here or they'd end up reflecting whatever key
				// happened to be tried last by the time the loop finishes.
				best = &Config{Offset: offset, Key: fmt.Sprintf("0x%02x", k), Entries: cloneEntries(entries)}
			}
		}
	}

	if best == nil {
		return nil, false
	}
	best.Settings = Decode(best.Entries)
	return best, true
}

func cloneEntries(entries []Entry) []Entry {
	out := make([]Entry, len(entries))
	for i, e := range entries {
		v := make([]byte, len(e.Value))
		copy(v, e.Value)
		out[i] = Entry{Index: e.Index, Type: e.Type, Length: e.Length, Value: v}
	}
	return out
}

func countKnown(entries []Entry) int {
	n := 0
	for _, e := range entries {
		if _, ok := catalog[int(e.Index)]; ok {
			n++
		}
	}
	return n
}

// findRepeatingKeyLayer looks for a stageless beacon's whole-section XOR
// key: scan 4-byte-aligned words and count how often each value repeats.
// Long stretches of zero-padding in the original image XOR to the key
// itself, so the most frequent word past the threshold is trusted as the
// key, and everything from just past the run where it was found onward is
// decrypted with it.
func findRepeatingKeyLayer(data []byte) ([]byte, bool) {
	counts := make(map[uint32]int)
	for i := 0; i+4 <= len(data); i += 4 {
		w := wordAt(data, i)
		if w != 0 {
			counts[w]++
		}
	}

	var keyWord uint32
	bestCount := 0
	for w, c := range counts {
		if c > bestCount {
			bestCount, keyWord = c, w
		}
	}
	if bestCount < repeatingKeyThreshold {
		return nil, false
	}

	key := []byte{byte(keyWord >> 24), byte(keyWord >> 16), byte(keyWord >> 8), byte(keyWord)}

	// The encrypted region starts right after the run of key-sized words
	// that led to this key (the padding used to find it), 16-byte aligned,
	// per the observed layout of stageless beacon loaders.
	start := 0
	for i := 0; i+4 <= len(data); i += 4 {
		if wordAt(data, i) == keyWord {
			start = i + 4
			break
		}
	}
	start += (16 - start%16) % 16
	if start >= len(data) {
		return nil, false
	}

	out := make([]byte, len(data)-start)
	for i, b := range data[start:] {
		out[i] = b ^ key[i%4]
	}
	return out, true
}

func wordAt(b []byte, i int) uint32 {
	return uint32(b[i])<<24 | uint32(b[i+1])<<16 | uint32(b[i+2])<<8 | uint32(b[i+3])
}

// KeyBytes parses a Config.Key description like "0x2e" or "3c 91 04 aa" back
// into raw bytes — used by tests to cross-check recovery against the key a
// fixture was built with.
func KeyBytes(desc string) ([]byte, error) {
	var out []byte
	cur := ""
	flush := func() error {
		if cur == "" {
			return nil
		}
		b, err := hex.DecodeString(trimHexPrefix(cur))
		if err != nil {
			return err
		}
		out = append(out, b...)
		cur = ""
		return nil
	}
	for _, r := range desc {
		if r == ' ' {
			if err := flush(); err != nil {
				return nil, err
			}
			continue
		}
		cur += string(r)
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return out, nil
}

func trimHexPrefix(s string) string {
	if len(s) > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		return s[2:]
	}
	return s
}
