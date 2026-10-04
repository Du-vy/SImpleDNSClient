//go:build windows
// +build windows

package windivert

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	LayerNetwork        = 0
	LayerNetworkForward = 1
	LayerFlow           = 2
	LayerSocket         = 3
	LayerReflect        = 4

	FlagSniff      = 0x0001
	FlagDrop       = 0x0002
	FlagNoChecksum = 0x0100

	InvalidHandle = windows.Handle(^uintptr(0))
)

// Address matches the 80-byte WINDIVERT_ADDRESS structure in WinDivert 2.2.
type Address struct {
	Timestamp int64
	Bits      uint32
	Reserved2 uint32
	IfIdx     uint32
	SubIfIdx  uint32
	Reserved3 [56]byte
}

func (a *Address) IsOutbound() bool {
	return (a.Bits & (1 << 17)) != 0
}

func (a *Address) SetOutbound(outbound bool) {
	if outbound {
		a.Bits |= (1 << 17)
	} else {
		a.Bits &^= (1 << 17)
	}
}

func (a *Address) IsLoopback() bool {
	return (a.Bits & (1 << 18)) != 0
}

func (a *Address) IsImpostor() bool {
	return (a.Bits & (1 << 19)) != 0
}

func (a *Address) SetImpostor(impostor bool) {
	if impostor {
		a.Bits |= (1 << 19)
	} else {
		a.Bits &^= (1 << 19)
	}
}

func (a *Address) IsIPv6() bool {
	return (a.Bits & (1 << 20)) != 0
}

func (a *Address) SetIPv6(v6 bool) {
	if v6 {
		a.Bits |= (1 << 20)
	} else {
		a.Bits &^= (1 << 20)
	}
}

var (
	loadOnce       sync.Once
	winDivertDLL   *windows.LazyDLL
	dllLoadErr     error

	procWinDivertOpen               *windows.LazyProc
	procWinDivertRecv               *windows.LazyProc
	procWinDivertSend               *windows.LazyProc
	procWinDivertClose              *windows.LazyProc
	procWinDivertHelperCalcChecksums *windows.LazyProc
)

// initDLL sets up search directories and prepares WinDivert function bindings.
func initDLL() error {
	loadOnce.Do(func() {
		// Try setting DLL directory to application dir or bin/ if WinDivert.dll is found there
		exePath, err := os.Executable()
		if err == nil {
			exeDir := filepath.Dir(exePath)
			if _, err := os.Stat(filepath.Join(exeDir, "WinDivert.dll")); err == nil {
				_ = windows.SetDllDirectory(exeDir)
			} else if _, err := os.Stat(filepath.Join(exeDir, "bin", "WinDivert.dll")); err == nil {
				_ = windows.SetDllDirectory(filepath.Join(exeDir, "bin"))
			}
		}

		if _, err := os.Stat(filepath.Join("bin", "WinDivert.dll")); err == nil {
			absBin, _ := filepath.Abs("bin")
			_ = windows.SetDllDirectory(absBin)
		}

		winDivertDLL = windows.NewLazyDLL("WinDivert.dll")
		if err := winDivertDLL.Load(); err != nil {
			dllLoadErr = fmt.Errorf("could not load WinDivert.dll: %w (make sure WinDivert.dll and WinDivert64.sys are in the application or bin/ directory)", err)
			return
		}

		procWinDivertOpen = winDivertDLL.NewProc("WinDivertOpen")
		procWinDivertRecv = winDivertDLL.NewProc("WinDivertRecv")
		procWinDivertSend = winDivertDLL.NewProc("WinDivertSend")
		procWinDivertClose = winDivertDLL.NewProc("WinDivertClose")
		procWinDivertHelperCalcChecksums = winDivertDLL.NewProc("WinDivertHelperCalcChecksums")
	})

	return dllLoadErr
}

// IsElevated checks whether the current Windows process has administrative privileges.
func IsElevated() bool {
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
	if err != nil {
		return false
	}
	defer token.Close()
	return token.IsElevated()
}

// Open opens a WinDivert handle with the specified filter and layer.
func Open(filter string, layer int32, priority int16, flags uint64) (windows.Handle, error) {
	if err := initDLL(); err != nil {
		return InvalidHandle, err
	}

	filterBytes, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return InvalidHandle, fmt.Errorf("invalid filter string: %w", err)
	}

	r0, _, err := procWinDivertOpen.Call(
		uintptr(unsafe.Pointer(filterBytes)),
		uintptr(layer),
		uintptr(priority),
		uintptr(flags),
	)

	h := windows.Handle(r0)
	if h == InvalidHandle || h == 0 {
		return InvalidHandle, fmt.Errorf("WinDivertOpen failed: %w", err)
	}
	return h, nil
}

// Recv receives a packet matching the filter from the WinDivert handle.
func Recv(handle windows.Handle, packetBuf []byte, addr *Address) (uint32, error) {
	var recvLen uint32
	r0, _, err := procWinDivertRecv.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&packetBuf[0])),
		uintptr(len(packetBuf)),
		uintptr(unsafe.Pointer(&recvLen)),
		uintptr(unsafe.Pointer(addr)),
	)
	if r0 == 0 {
		return 0, fmt.Errorf("WinDivertRecv failed: %w", err)
	}
	return recvLen, nil
}

// Send injects a packet into the network stack via the WinDivert handle.
func Send(handle windows.Handle, packetBuf []byte, addr *Address) (uint32, error) {
	var sendLen uint32
	r0, _, err := procWinDivertSend.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&packetBuf[0])),
		uintptr(len(packetBuf)),
		uintptr(unsafe.Pointer(&sendLen)),
		uintptr(unsafe.Pointer(addr)),
	)
	if r0 == 0 {
		return 0, fmt.Errorf("WinDivertSend failed: %w", err)
	}
	return sendLen, nil
}

// Close closes the WinDivert handle and automatically unregisters the WFP filter.
func Close(handle windows.Handle) error {
	if handle == InvalidHandle || handle == 0 {
		return nil
	}
	r0, _, err := procWinDivertClose.Call(uintptr(handle))
	if r0 == 0 {
		return fmt.Errorf("WinDivertClose failed: %w", err)
	}
	return nil
}

// HelperCalcChecksums uses WinDivert's native helper function to compute packet checksums.
func HelperCalcChecksums(packetBuf []byte, addr *Address, flags uint64) uint32 {
	if procWinDivertHelperCalcChecksums == nil {
		return 0
	}
	r0, _, _ := procWinDivertHelperCalcChecksums.Call(
		uintptr(unsafe.Pointer(&packetBuf[0])),
		uintptr(len(packetBuf)),
		uintptr(unsafe.Pointer(addr)),
		uintptr(flags),
	)
	return uint32(r0)
}
