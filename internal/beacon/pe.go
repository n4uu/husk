package beacon

import (
	"bytes"
	"debug/pe"
)

// Source is one region of an input file worth searching for a config —
// searching sections individually before falling back to the whole file
// keeps false-positive structural matches (see recover.go) rare, since a
// section boundary is a much smaller haystack than an entire binary.
type Source struct {
	Name string
	Data []byte
}

// sectionPriority lists PE sections in the order Beacon has been observed
// to place its configuration in: .data for ordinary builds, .rdata for some
// stageless variants, .text as a last resort for anything unusual.
var sectionPriority = []string{".data", ".rdata", ".text"}

// Sources returns the regions of raw worth searching, in priority order. If
// raw doesn't parse as a PE at all, it's returned as the sole, whole-file
// source — the caller (a raw section dump, a memory-dumped shellcode blob,
// an already-decrypted stager) is handled the same way either path.
func Sources(raw []byte) []Source {
	f, err := pe.NewFile(bytes.NewReader(raw))
	if err != nil {
		return []Source{{Name: "raw input", Data: raw}}
	}
	defer f.Close()

	byName := make(map[string]*pe.Section, len(f.Sections))
	for _, s := range f.Sections {
		byName[s.Name] = s
	}

	var sources []Source
	for _, name := range sectionPriority {
		s, ok := byName[name]
		if !ok {
			continue
		}
		data, err := s.Data()
		if err != nil || len(data) == 0 {
			continue
		}
		sources = append(sources, Source{Name: "PE section " + name, Data: data})
	}

	// However the config wasn't in one of the usual sections — an unusual
	// build, a packed loader — fall back to the whole file so it's still
	// found.
	sources = append(sources, Source{Name: "whole file", Data: raw})

	return sources
}
