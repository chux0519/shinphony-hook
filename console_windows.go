package main

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32Console           = windows.NewLazySystemDLL("kernel32.dll")
	procGetConsoleProcessList = kernel32Console.NewProc("GetConsoleProcessList")
	procFreeConsole           = kernel32Console.NewProc("FreeConsole")
)

// detachOwnConsole closes the console window Windows opened for this process
// when the scheduled task runs the Hook directly (older Windows without
// `conhost.exe --headless`, TF 161). A console this process shares with a shell
// (someone ran `supervise` from a terminal) is kept: only a console whose sole
// process is this one was created for it.
func detachOwnConsole() {
	if consoleOwnedAlone(consoleProcessCount()) {
		_, _, _ = procFreeConsole.Call()
	}
}

// consoleProcessCount is how many processes share this process's console; 0
// when it has none or the count is unavailable.
func consoleProcessCount() int {
	if procGetConsoleProcessList.Find() != nil || procFreeConsole.Find() != nil {
		return 0
	}
	var ids [4]uint32
	n, _, _ := procGetConsoleProcessList.Call(uintptr(unsafe.Pointer(&ids[0])), uintptr(len(ids)))
	return int(n)
}
