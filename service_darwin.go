package main

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

func xmlText(s string) string { var b bytes.Buffer; xml.EscapeText(&b, []byte(s)); return b.String() }
func launchPath(dir string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents", serviceName(dir)+".plist"), nil
}
func installService(dir, creds string) error {
	exe, err := serviceExecutable(dir)
	if err != nil {
		return err
	}
	path, err := launchPath(dir)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	body := `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>Label</key><string>` + serviceName(dir) + `</string><key>ProgramArguments</key><array>`
	for _, a := range []string{exe, "--state-dir", dir, "--credentials-dir", creds, "serve"} {
		body += "<string>" + xmlText(a) + "</string>"
	}
	body += `</array><key>RunAtLoad</key><true/><key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict><key>ThrottleInterval</key><integer>10</integer><key>ProcessType</key><string>Background</string><key>Umask</key><integer>63</integer><key>StandardOutPath</key><string>/dev/null</string><key>StandardErrorPath</key><string>/dev/null</string></dict></plist>`
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("service_already_exists_or_path_unavailable")
	}
	_, err = f.WriteString(body)
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	domain := "gui/" + strconv.Itoa(os.Getuid())
	if err = serviceCommand("/bin/launchctl", "bootstrap", domain, path); err != nil {
		os.Remove(path)
		return err
	}
	if err = awaitService(dir); err != nil {
		return err
	}
	fmt.Println(`{"installed":true,"scope":"logged-in-user","service":"` + serviceName(dir) + `"}`)
	return nil
}
func uninstallService(dir string) error {
	path, err := launchPath(dir)
	if err != nil {
		return err
	}
	if err = privatePath(path, false); err != nil {
		return err
	}
	if err = serviceCommand("/bin/launchctl", "bootout", "gui/"+strconv.Itoa(os.Getuid()), path); err != nil {
		return err
	}
	if err = os.Remove(path); err != nil {
		return err
	}
	return awaitStopped(dir)
}
