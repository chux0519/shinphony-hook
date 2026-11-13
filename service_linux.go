package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func unitArg(s string) (string, error) {
	if strings.ContainsAny(s, "\r\n\x00") {
		return "", errors.New("invalid_unit_path")
	}
	s = strings.ReplaceAll(s, "%", "%%")
	s = strings.ReplaceAll(s, "$", "$$")
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return "\"" + s + "\"", nil
}
func unitPath(dir string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "systemd", "user", serviceName(dir)+".service"), nil
}
func installService(dir, creds string) error {
	exe, err := serviceExecutable(dir)
	if err != nil {
		return err
	}
	path, err := unitPath(dir)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	args := []string{}
	for _, s := range []string{exe, "--state-dir", dir, "--credentials-dir", creds, "serve"} {
		a, err := unitArg(s)
		if err != nil {
			return err
		}
		args = append(args, a)
	}
	body := "[Unit]\nDescription=Shinphony Hook\nStartLimitIntervalSec=60\nStartLimitBurst=3\n[Service]\nType=simple\nExecStart=" + strings.Join(args, " ") + "\nRestart=on-failure\nRestartSec=5\nUMask=0077\nNoNewPrivileges=true\nMemoryMax=128M\nCPUQuota=10%\nTasksMax=32\nStandardOutput=null\nStandardError=journal\n[Install]\nWantedBy=default.target\n"
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("service_already_exists_or_path_unavailable")
	}
	_, err = f.WriteString(body)
	ce := f.Close()
	if err != nil {
		return err
	}
	if ce != nil {
		return ce
	}
	if err = serviceCommand("systemctl", "--user", "daemon-reload"); err != nil {
		return err
	}
	if err = serviceCommand("systemctl", "--user", "enable", "--now", filepath.Base(path)); err != nil {
		return err
	}
	if err = awaitService(dir); err != nil {
		return err
	}
	fmt.Println(`{"installed":true,"scope":"user-manager","service":"` + filepath.Base(path) + `"}`)
	return nil
}
func uninstallService(dir string) error {
	path, err := unitPath(dir)
	if err != nil {
		return err
	}
	if err = privatePath(path, false); err != nil {
		return err
	}
	if err = serviceCommand("systemctl", "--user", "disable", "--now", filepath.Base(path)); err != nil {
		return err
	}
	if err = os.Remove(path); err != nil {
		return err
	}
	if err = serviceCommand("systemctl", "--user", "daemon-reload"); err != nil {
		return err
	}
	return awaitStopped(dir)
}
