package beacon

import (
	"bytes"
	"encoding/binary"
)

// BuildMinimalPE wraps sectionData in the smallest PE32 file the standard
// library's debug/pe will parse: a DOS header, a COFF header, a full
// IMAGE_OPTIONAL_HEADER32 (all 16 data directories present, all zeroed,
// since this fixture has no imports, exports or relocations to describe),
// and a single ".data" section. Every field is filled with a real,
// spec-correct value rather than left zero where the format allows it: the
// point of building this by hand is to prove husk's PE section reader
// really walks a standards-compliant section table, not to see how much a
// lenient parser will let us skip.
func BuildMinimalPE(sectionData []byte) []byte {
	const (
		fileAlign    = 0x200
		sectionAlign = 0x1000
		imageBase    = 0x00400000
		numSections  = 1
		optHeaderLen = 224 // IMAGE_OPTIONAL_HEADER32 with 16 data directories
	)

	dosHeaderLen := 64
	peHeaderOffset := uint32(dosHeaderLen)
	coffLen := 20
	sectionTableOffset := int(peHeaderOffset) + 4 + coffLen + optHeaderLen
	sectionTableLen := numSections * 40
	headersLen := sectionTableOffset + sectionTableLen
	sizeOfHeaders := roundUp(headersLen, fileAlign)

	rawDataSize := roundUp(len(sectionData), fileAlign)
	pointerToRawData := sizeOfHeaders
	sizeOfImage := roundUp(sectionAlign+roundUp(len(sectionData), sectionAlign), sectionAlign)

	var f bytes.Buffer

	// --- DOS header (64 bytes): only e_magic and e_lfanew matter here. ---
	dos := make([]byte, dosHeaderLen)
	dos[0], dos[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(dos[0x3C:], peHeaderOffset)
	f.Write(dos)

	// --- PE signature + COFF file header ---
	f.WriteString("PE\x00\x00")
	coff := make([]byte, coffLen)
	binary.LittleEndian.PutUint16(coff[0:2], 0x14c)       // Machine: IMAGE_FILE_MACHINE_I386
	binary.LittleEndian.PutUint16(coff[2:4], numSections) // NumberOfSections
	binary.LittleEndian.PutUint32(coff[4:8], 0)           // TimeDateStamp
	binary.LittleEndian.PutUint32(coff[8:12], 0)          // PointerToSymbolTable
	binary.LittleEndian.PutUint32(coff[12:16], 0)         // NumberOfSymbols
	binary.LittleEndian.PutUint16(coff[16:18], uint16(optHeaderLen))
	binary.LittleEndian.PutUint16(coff[18:20], 0x0102) // EXECUTABLE_IMAGE | 32BIT_MACHINE
	f.Write(coff)

	// --- Optional header (IMAGE_OPTIONAL_HEADER32) ---
	opt := make([]byte, optHeaderLen)
	binary.LittleEndian.PutUint16(opt[0:2], 0x10b)                  // Magic: PE32
	opt[2], opt[3] = 14, 0                                          // Linker version
	binary.LittleEndian.PutUint32(opt[4:8], 0)                      // SizeOfCode
	binary.LittleEndian.PutUint32(opt[8:12], uint32(rawDataSize))   // SizeOfInitializedData
	binary.LittleEndian.PutUint32(opt[12:16], 0)                    // SizeOfUninitializedData
	binary.LittleEndian.PutUint32(opt[16:20], uint32(sectionAlign)) // AddressOfEntryPoint
	binary.LittleEndian.PutUint32(opt[20:24], uint32(sectionAlign)) // BaseOfCode
	binary.LittleEndian.PutUint32(opt[24:28], uint32(sectionAlign)) // BaseOfData
	binary.LittleEndian.PutUint32(opt[28:32], imageBase)
	binary.LittleEndian.PutUint32(opt[32:36], sectionAlign)
	binary.LittleEndian.PutUint32(opt[36:40], fileAlign)
	binary.LittleEndian.PutUint16(opt[40:42], 6) // MajorOperatingSystemVersion
	binary.LittleEndian.PutUint16(opt[42:44], 0)
	binary.LittleEndian.PutUint16(opt[44:46], 0) // MajorImageVersion
	binary.LittleEndian.PutUint16(opt[46:48], 0)
	binary.LittleEndian.PutUint16(opt[48:50], 6) // MajorSubsystemVersion
	binary.LittleEndian.PutUint16(opt[50:52], 0)
	binary.LittleEndian.PutUint32(opt[52:56], 0)                     // Win32VersionValue
	binary.LittleEndian.PutUint32(opt[56:60], uint32(sizeOfImage))   // SizeOfImage
	binary.LittleEndian.PutUint32(opt[60:64], uint32(sizeOfHeaders)) // SizeOfHeaders
	binary.LittleEndian.PutUint32(opt[64:68], 0)                     // CheckSum
	binary.LittleEndian.PutUint16(opt[68:70], 3)                     // Subsystem: WINDOWS_CUI
	binary.LittleEndian.PutUint16(opt[70:72], 0)                     // DllCharacteristics
	binary.LittleEndian.PutUint32(opt[72:76], 0x100000)              // SizeOfStackReserve
	binary.LittleEndian.PutUint32(opt[76:80], 0x1000)                // SizeOfStackCommit
	binary.LittleEndian.PutUint32(opt[80:84], 0x100000)              // SizeOfHeapReserve
	binary.LittleEndian.PutUint32(opt[84:88], 0x1000)                // SizeOfHeapCommit
	binary.LittleEndian.PutUint32(opt[88:92], 0)                     // LoaderFlags
	binary.LittleEndian.PutUint32(opt[92:96], 16)                    // NumberOfRvaAndSizes
	// Data directories (16 * 8 bytes) are left zeroed: this fixture has no
	// import/export/relocation tables to point to.
	f.Write(opt)

	// --- Section header table ---
	section := make([]byte, 40)
	copy(section[0:8], ".data")
	binary.LittleEndian.PutUint32(section[8:12], uint32(len(sectionData))) // VirtualSize
	binary.LittleEndian.PutUint32(section[12:16], sectionAlign)            // VirtualAddress
	binary.LittleEndian.PutUint32(section[16:20], uint32(rawDataSize))     // SizeOfRawData
	binary.LittleEndian.PutUint32(section[20:24], uint32(pointerToRawData))
	binary.LittleEndian.PutUint32(section[24:28], 0)          // PointerToRelocations
	binary.LittleEndian.PutUint32(section[28:32], 0)          // PointerToLinenumbers
	binary.LittleEndian.PutUint16(section[32:34], 0)          // NumberOfRelocations
	binary.LittleEndian.PutUint16(section[34:36], 0)          // NumberOfLinenumbers
	binary.LittleEndian.PutUint32(section[36:40], 0xC0000040) // INITIALIZED_DATA|READ|WRITE
	f.Write(section)

	// --- Pad headers to SizeOfHeaders, then write the section's raw data ---
	padTo(&f, sizeOfHeaders)
	f.Write(sectionData)
	padTo(&f, pointerToRawData+rawDataSize)

	return f.Bytes()
}

func roundUp(v, align int) int {
	if v%align == 0 {
		return v
	}
	return v + (align - v%align)
}

func padTo(buf *bytes.Buffer, size int) {
	if n := size - buf.Len(); n > 0 {
		buf.Write(make([]byte, n))
	}
}
