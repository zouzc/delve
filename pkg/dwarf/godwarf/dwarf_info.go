package godwarf

// DW_LANG_Go (from DWARF v5, section 7.12, page 231)
const DwarfGoLanguage = 22

// DwarfInfo holds all of the information
// parsed from every DWARF section in every
// object file that has been linked into the
// process being debugged.
type DwarfInfo struct {
	// DebugInfoDirectories is a list of all directories to look it
	// where DWARF debug information may be kept. Generally this is
	// the same as the binary, but several distrubutions will ship
	// debug informatio seperate from the actual binary.
	DebugInfoDirectories []string
}
