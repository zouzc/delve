package proc

import (
	"encoding/binary"
	"fmt"
	"go/constant"
	"reflect"
	"strings"

	"github.com/go-delve/delve/pkg/dwarf/godwarf"
)

// G status, from: src/runtime/runtime2.go
const (
	Gidle           uint64 = iota // 0
	Grunnable                     // 1 runnable and on a run queue
	Grunning                      // 2
	Gsyscall                      // 3
	Gwaiting                      // 4
	GmoribundUnused               // 5 currently unused, but hardcoded in gdb scripts
	Gdead                         // 6
	Genqueue                      // 7 Only the Gscanenqueue is used.
	Gcopystack                    // 8 in this state when newstack is moving the stack
)

// G represents a runtime G (goroutine) structure (at least the
// fields that Delve is interested in).
type G struct {
	ID         int    // Goroutine ID
	PC         uint64 // PC of goroutine when it was parked.
	SP         uint64 // SP of goroutine when it was parked.
	BP         uint64 // BP of goroutine when it was parked (go >= 1.7).
	GoPC       uint64 // PC of 'go' statement that created this goroutine.
	StartPC    uint64 // PC of the first function run on this goroutine.
	WaitReason string // Reason for goroutine being parked.
	Status     uint64
	stkbarVar  *Variable // stkbar field of g struct
	stkbarPos  int       // stkbarPos field of g struct
	stackhi    uint64    // value of stack.hi
	stacklo    uint64    // value of stack.lo

	SystemStack bool // SystemStack is true if this goroutine is currently executing on a system stack.

	// Information on goroutine location
	CurrentLoc Location

	// Thread that this goroutine is currently allocated to
	Thread Thread

	variable *Variable

	Unreadable error // could not read the G struct
}

// Defer returns the top-most defer of the goroutine.
func (g *G) Defer() *Defer {
	if g.variable.Unreadable != nil {
		return nil
	}
	dvar := g.variable.fieldVariable("_defer").maybeDereference()
	if dvar.Addr == 0 {
		return nil
	}
	d := &Defer{variable: dvar}
	d.load()
	return d
}

// UserCurrent returns the location the users code is at,
// or was at before entering a runtime function.
func (g *G) UserCurrent() Location {
	it, err := g.stackIterator()
	if err != nil {
		return g.CurrentLoc
	}
	for it.Next() {
		frame := it.Frame()
		if frame.Call.Fn != nil {
			name := frame.Call.Fn.Name
			if strings.Contains(name, ".") && (!strings.HasPrefix(name, "runtime.") || isExportedRuntime(name)) {
				return frame.Call
			}
		}
	}
	return g.CurrentLoc
}

// Go returns the location of the 'go' statement
// that spawned this goroutine.
func (g *G) Go() Location {
	pc := g.GoPC
	if fn := g.variable.bi.PCToFunc(pc); fn != nil {
		// Backup to CALL instruction.
		// Mimics runtime/traceback.go:677.
		if g.GoPC > fn.Entry {
			pc--
		}
	}
	f, l, fn := g.variable.bi.PCToLine(pc)
	return Location{PC: g.GoPC, File: f, Line: l, Fn: fn}
}

// StartLoc returns the starting location of the goroutine.
func (g *G) StartLoc() Location {
	f, l, fn := g.variable.bi.PCToLine(g.StartPC)
	return Location{PC: g.StartPC, File: f, Line: l, Fn: fn}
}

// Ancestor represents a goroutines ancestor,
// e.g. the goroutine which spawned this goroutine.
type Ancestor struct {
	ID         int64 // Goroutine ID
	Unreadable error
	pcsVar     *Variable
}

// Returns the list of saved return addresses used by stack barriers
func (g *G) stkbar() ([]savedLR, error) {
	if g.stkbarVar == nil { // stack barriers were removed in Go 1.9
		return nil, nil
	}
	g.stkbarVar.loadValue(LoadConfig{false, 1, 0, int(g.stkbarVar.Len), 3, 0})
	if g.stkbarVar.Unreadable != nil {
		return nil, fmt.Errorf("unreadable stkbar: %v", g.stkbarVar.Unreadable)
	}
	r := make([]savedLR, len(g.stkbarVar.Children))
	for i, child := range g.stkbarVar.Children {
		for _, field := range child.Children {
			switch field.Name {
			case "savedLRPtr":
				ptr, _ := constant.Int64Val(field.Value)
				r[i].ptr = uint64(ptr)
			case "savedLRVal":
				val, _ := constant.Int64Val(field.Value)
				r[i].val = uint64(val)
			}
		}
	}
	return r, nil
}

func parseG(v *Variable) (*G, error) {
	mem := v.mem
	gaddr := uint64(v.Addr)
	_, deref := v.RealType.(*godwarf.PtrType)

	if deref {
		gaddrbytes := make([]byte, v.bi.Arch.PtrSize())
		_, err := mem.ReadMemory(gaddrbytes, uintptr(gaddr))
		if err != nil {
			return nil, fmt.Errorf("error derefing *G %s", err)
		}
		gaddr = binary.LittleEndian.Uint64(gaddrbytes)
	}
	if gaddr == 0 {
		id := 0
		if thread, ok := mem.(Thread); ok {
			id = thread.ThreadID()
		}
		return nil, ErrNoGoroutine{tid: id}
	}
	for {
		if _, isptr := v.RealType.(*godwarf.PtrType); !isptr {
			break
		}
		v = v.maybeDereference()
	}
	v.loadValue(LoadConfig{false, 2, 64, 0, -1, 0})
	if v.Unreadable != nil {
		return nil, v.Unreadable
	}
	schedVar := v.fieldVariable("sched")
	pc, _ := constant.Int64Val(schedVar.fieldVariable("pc").Value)
	sp, _ := constant.Int64Val(schedVar.fieldVariable("sp").Value)
	var bp int64
	if bpvar := schedVar.fieldVariable("bp"); bpvar != nil && bpvar.Value != nil {
		bp, _ = constant.Int64Val(bpvar.Value)
	}
	id, _ := constant.Int64Val(v.fieldVariable("goid").Value)
	gopc, _ := constant.Int64Val(v.fieldVariable("gopc").Value)
	startpc, _ := constant.Int64Val(v.fieldVariable("startpc").Value)
	waitReason := ""
	if wrvar := v.fieldVariable("waitreason"); wrvar.Value != nil {
		switch wrvar.Kind {
		case reflect.String:
			waitReason = constant.StringVal(wrvar.Value)
		case reflect.Uint:
			waitReason = wrvar.ConstDescr()
		}

	}
	var stackhi, stacklo uint64
	if stackVar := v.fieldVariable("stack"); stackVar != nil {
		if stackhiVar := stackVar.fieldVariable("hi"); stackhiVar != nil {
			stackhi, _ = constant.Uint64Val(stackhiVar.Value)
		}
		if stackloVar := stackVar.fieldVariable("lo"); stackloVar != nil {
			stacklo, _ = constant.Uint64Val(stackloVar.Value)
		}
	}

	stkbarVar, _ := v.structMember("stkbar")
	stkbarVarPosFld := v.fieldVariable("stkbarPos")
	var stkbarPos int64
	if stkbarVarPosFld != nil { // stack barriers were removed in Go 1.9
		stkbarPos, _ = constant.Int64Val(stkbarVarPosFld.Value)
	}

	status, _ := constant.Int64Val(v.fieldVariable("atomicstatus").Value)
	f, l, fn := v.bi.PCToLine(uint64(pc))
	g := &G{
		ID:         int(id),
		GoPC:       uint64(gopc),
		StartPC:    uint64(startpc),
		PC:         uint64(pc),
		SP:         uint64(sp),
		BP:         uint64(bp),
		WaitReason: waitReason,
		Status:     uint64(status),
		CurrentLoc: Location{PC: uint64(pc), File: f, Line: l, Fn: fn},
		variable:   v,
		stkbarVar:  stkbarVar,
		stkbarPos:  int(stkbarPos),
		stackhi:    stackhi,
		stacklo:    stacklo,
	}
	return g, nil
}

func getGVariable(thread Thread) (*Variable, error) {
	regs, err := thread.Registers(false)
	if err != nil {
		return nil, err
	}

	gaddr, hasgaddr := regs.GAddr()
	if !hasgaddr {
		gaddrbs := make([]byte, thread.Arch().PtrSize())
		_, err := thread.ReadMemory(gaddrbs, uintptr(regs.TLS()+thread.BinInfo().GStructOffset()))
		if err != nil {
			return nil, err
		}
		gaddr = binary.LittleEndian.Uint64(gaddrbs)
	}

	return newGVariable(thread, uintptr(gaddr), thread.Arch().DerefTLS())
}

func newGVariable(thread Thread, gaddr uintptr, deref bool) (*Variable, error) {
	typ, err := thread.BinInfo().findType("runtime.g")
	if err != nil {
		return nil, err
	}

	name := ""

	if deref {
		typ = &godwarf.PtrType{
			CommonType: godwarf.CommonType{
				ByteSize:    int64(thread.Arch().PtrSize()),
				Name:        "",
				ReflectKind: reflect.Ptr,
				Offset:      0,
			},
			Type: typ,
		}
	} else {
		name = "runtime.curg"
	}

	return newVariableFromThread(thread, name, gaddr, typ), nil
}
