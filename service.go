package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

// Ensure only replaces a running, identified agent. Unknown/legacy service
// registrations are deliberately not overwritten. Database and credentials stay
// in place, and a failed replacement restores the previous executable.
func ensureService(dir, creds string) error {
	return ensureServiceMode(dir, creds, false)
}

func ensureServiceMode(dir, creds string, automatic bool) error {
	lock := filepath.Join(dir, "lifecycle")
	if err := prepareDir(lock); err != nil {
		return err
	}
	unlock, err := lockDir(lock)
	if err != nil {
		return errors.New("service_update_busy")
	}
	defer unlock()
	marker := filepath.Join(dir, "updates-disabled")
	if automatic {
		if _, e := os.Lstat(marker); e == nil || !os.IsNotExist(e) {
			return errors.New("automatic_updates_disabled")
		}
	} else {
		// Only a user-requested installation may undo an uninstall tombstone.
		if e := os.Remove(marker); e != nil && !os.IsNotExist(e) {
			return e
		}
	}
	exe, err := serviceExecutable(dir)
	if err != nil {
		return err
	}
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dialLocal(ctx, dir) }}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: 2 * time.Second}
	r, err := c.Get("http://local/v1/status")
	if err != nil {
		if automatic {
			return errors.New("service_unavailable_update_cancelled")
		}
		return installService(dir, creds)
	}
	defer r.Body.Close()
	var status struct {
		Executable      string `json:"executable"`
		Credentials     string `json:"credentialsDirectory"`
		ReleaseSequence int64  `json:"releaseSequence"`
	}
	if r.StatusCode != 200 || json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&status) != nil || status.Credentials != creds {
		return errors.New("service_upgrade_requires_recovery")
	}
	if status.Executable == exe {
		fmtInstalled()
		return nil
	}
	if status.ReleaseSequence > sequence() {
		return errors.New("service_downgrade_refused")
	}
	if status.ReleaseSequence != 0 && status.ReleaseSequence == sequence() {
		return errors.New("release_sequence_conflict")
	}
	old := status.Executable
	if filepath.Dir(old) != filepath.Clean(dir) || privatePath(old, false) != nil {
		return errors.New("service_upgrade_requires_recovery")
	}
	data, err := os.ReadFile(old)
	if err != nil {
		return err
	}
	if !matchesManagedBinary(old, data) {
		return errors.New("binary_digest_mismatch")
	}
	if err = uninstallService(dir); err != nil {
		return err
	}
	if err = installService(dir, creds); err == nil {
		return nil
	}
	// Installation may have registered the new service before readiness failed.
	_ = uninstallService(dir)
	if restore := serviceCommand(old, "--state-dir", dir, "--credentials-dir", creds, "install-service"); restore != nil {
		return errors.New("service_upgrade_and_rollback_failed")
	}
	return errors.New("service_upgrade_failed_previous_restored")
}

func uninstallRequested(dir string) error {
	lock := filepath.Join(dir, "lifecycle")
	if err := prepareDir(lock); err != nil {
		return err
	}
	unlock, err := lockDir(lock)
	if err != nil {
		return errors.New("service_update_busy")
	}
	defer unlock()
	marker := filepath.Join(dir, "updates-disabled")
	if _, err = os.Lstat(marker); err == nil {
		if err = privatePath(marker, false); err != nil {
			return err
		}
	} else if os.IsNotExist(err) {
		f, e := os.OpenFile(marker, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return e
		}
		e = f.Sync()
		ce := f.Close()
		if e != nil {
			return e
		}
		if ce != nil {
			return ce
		}
	} else {
		return err
	}
	return uninstallService(dir)
}

func fmtInstalled() { os.Stdout.WriteString("{\"installed\":true,\"unchanged\":true}\n") }

func serviceName(dir string) string {
	sum := sha256.Sum256([]byte(filepath.Clean(dir)))
	// Keep the registration identity stable across the CLI rename so ensure-
	// service replaces the old daemon instead of installing a second service.
	return "net.potafree.shinphony.agent." + hex.EncodeToString(sum[:6])
}
func serviceCommand(command string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, command, args...)
	if err := cmd.Run(); err != nil {
		return errors.New("service_manager_failed: " + command)
	}
	return nil
}
func executablePath() (string, error) {
	p, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(p)
}

func awaitService(dir string) error {
	expected, err := serviceExecutable(dir)
	if err != nil {
		return err
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dialLocal(ctx, dir) }}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get("http://localhost/v1/status")
		if err == nil {
			var status struct {
				Executable string `json:"executable"`
			}
			decodeErr := json.NewDecoder(io.LimitReader(resp.Body, 8192)).Decode(&status)
			resp.Body.Close()
			if resp.StatusCode == 200 && decodeErr == nil && status.Executable == expected {
				return nil
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return errors.New("service_registered_but_not_ready: inspect service manager; uninstall-service preserves data")
}

func awaitStopped(dir string) error {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		conn, err := dialLocal(ctx, dir)
		cancel()
		if err != nil {
			return nil
		}
		conn.Close()
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("service_stop_pending")
}

// Services run an immutable private copy, not a binary on a removable volume
// or in the caller's temporary build directory. Old copies enable rollback.
func serviceExecutable(dir string) (string, error) {
	source, err := executablePath()
	if err != nil {
		return "", err
	}
	f, err := os.Open(source)
	if err != nil {
		return "", err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 64*1024*1024+1))
	if err != nil || len(data) > 64*1024*1024 {
		return "", errors.New("invalid_binary_size")
	}
	digest := sha256.Sum256(data)
	name := managedPrefix + hex.EncodeToString(digest[:])
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	path := filepath.Join(dir, name)
	out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	if os.IsExist(err) {
		if err = privatePath(path, false); err != nil {
			return "", err
		}
		old, err := os.ReadFile(path)
		if err != nil || sha256.Sum256(old) != digest {
			return "", errors.New("binary_digest_mismatch")
		}
		return path, nil
	}
	if err != nil {
		return "", err
	}
	_, err = out.Write(data)
	if err == nil {
		err = out.Sync()
	}
	closeErr := out.Close()
	if err != nil {
		os.Remove(path)
		return "", err
	}
	if closeErr != nil {
		return "", closeErr
	}
	return path, privatePath(path, false)
}
