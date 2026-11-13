package main

import (
	"errors"
	"golang.org/x/sys/windows"
	"os/exec"
	"syscall"
	"time"
	"unsafe"
)

// Task Scheduler does not reliably restart an on-demand task after its process
// is forcibly terminated. Supervise the worker explicitly, with bounded bursts.
// The task owns the entire process tree; uninstall terminates both processes.
func supervise(dir, creds string) error {
	if err := supervisorJob(); err != nil {
		return err
	}
	exe, err := executablePath()
	if err != nil {
		return err
	}
	failures := []time.Time{}
	for {
		cmd := exec.Command(exe, "--state-dir", dir, "--credentials-dir", creds, "serve")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		if err = cmd.Run(); err == nil {
			return nil
		}
		now := time.Now()
		kept := failures[:0]
		for _, t := range failures {
			if now.Sub(t) < time.Minute {
				kept = append(kept, t)
			}
		}
		failures = append(kept, now)
		if len(failures) >= 3 {
			return errors.New("worker_restart_limit_reached")
		}
		time.Sleep(2 * time.Second)
	}
}

// Bind the supervisor itself before spawning so workers inherit this job
// atomically. Closing the last handle on supervisor exit kills every child,
// including when Task Scheduler terminates only the supervisor process.
func supervisorJob() error {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		windows.CloseHandle(job)
		return err
	}
	if err = windows.AssignProcessToJobObject(job, windows.CurrentProcess()); err != nil {
		windows.CloseHandle(job)
		return err
	}
	// Intentionally process-lifetime, non-inheritable handle. The OS closes it
	// on exit; closing here would terminate the supervisor immediately.
	return nil
}
