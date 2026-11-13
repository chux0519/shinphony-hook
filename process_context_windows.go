//go:build windows

package main

import (
	"context"
	"golang.org/x/sys/windows"
	"strconv"
	"unsafe"
)

func processStart(ctx context.Context, pid int) string {
	if ctx.Err() != nil || pid <= 1 {
		return ""
	}
	handle, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if e != nil {
		return ""
	}
	defer windows.CloseHandle(handle)
	var created, exit, kernel, user windows.Filetime
	if windows.GetProcessTimes(handle, &created, &exit, &kernel, &user) != nil {
		return ""
	}
	return strconv.FormatUint(uint64(created.HighDateTime)<<32|uint64(created.LowDateTime), 10)
}
func processEntry(ctx context.Context, pid int) *windows.ProcessEntry32 {
	if ctx.Err() != nil || pid <= 1 {
		return nil
	}
	snapshot, e := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if e != nil {
		return nil
	}
	defer windows.CloseHandle(snapshot)
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	for e = windows.Process32First(snapshot, &entry); e == nil; e = windows.Process32Next(snapshot, &entry) {
		if int(entry.ProcessID) == pid {
			return &entry
		}
		if ctx.Err() != nil {
			return nil
		}
	}
	return nil
}
func processParent(ctx context.Context, pid int) int {
	e := processEntry(ctx, pid)
	if e == nil {
		return 0
	}
	return int(e.ParentProcessID)
}
func processName(ctx context.Context, pid int) string {
	e := processEntry(ctx, pid)
	if e == nil {
		return ""
	}
	return windows.UTF16ToString(e.ExeFile[:])
}

// processEnv: Windows hooks keep their environment; nothing to recover.
func processEnv(ctx context.Context, pid int) map[string]string { return map[string]string{} }
