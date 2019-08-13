package loc

import "encoding/binary"

type LoclistReader struct {
	data  []byte
	cur   int
	ptrSz int
}

type LoclistEntry struct {
	lowpc, highpc uint64
	instr         []byte
}

func NewLoclistReader(data []byte, ptrSz int) *LoclistReader {
	return &LoclistReader{data: data, ptrSz: ptrSz}
}

func (e *LoclistEntry) BaseAddressSelection() bool {
	return e.lowpc == ^uint64(0)
}

func (e *LoclistEntry) HighPC() uint64 {
	return e.highpc
}

func (e *LoclistEntry) LowPC() uint64 {
	return e.lowpc
}

func (e *LoclistEntry) Instr() []byte {
	return e.instr
}

func (r *LoclistReader) Seek(off int) {
	r.cur = off
}

func (r *LoclistReader) read(sz int) []byte {
	data := r.data[r.cur : r.cur+sz]
	r.cur += sz
	return data
}

func (r *LoclistReader) oneAddr() uint64 {
	switch r.ptrSz {
	case 4:
		addr := binary.LittleEndian.Uint32(r.read(r.ptrSz))
		if addr == ^uint32(0) {
			return ^uint64(0)
		}
		return uint64(addr)
	case 8:
		addr := uint64(binary.LittleEndian.Uint64(r.read(r.ptrSz)))
		return addr
	default:
		panic("bad address size")
	}
}

func (r *LoclistReader) Next(e *LoclistEntry) bool {
	e.lowpc = r.oneAddr()
	e.highpc = r.oneAddr()

	if e.lowpc == 0 && e.highpc == 0 {
		return false
	}

	if e.BaseAddressSelection() {
		e.instr = nil
		return true
	}

	instrlen := binary.LittleEndian.Uint16(r.read(2))
	e.instr = r.read(int(instrlen))
	return true
}
