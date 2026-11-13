package main

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

//go:embed assets/task-notify/SKILL.md
var taskSkill []byte

// SHA-256 of earlier embedded SKILL.md versions, replaced on upgrade. Any
// other content is a user edit and is preserved.
var previousTaskSkills = map[string]bool{
	"e67f8516c2d25036c4d960c9095ab0cfb32b842f8b73c8afb1c78cd283f84d0e": true, // 2026-11-02: direct IPC before Codex intent handoff
	"6893f87725a5bd4f9c6d1bfec9dc95516f2e3c819905578f2e68c587282807e5": true, // 2026-10-24: tmux context required
}

func writePrivateFile(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".skill-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if ce := f.Close(); err == nil {
		err = ce
	}
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func installTaskSkill(exe string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	base := os.Getenv("CODEX_HOME")
	if base == "" {
		base = filepath.Join(home, ".codex")
	}
	parent := filepath.Join(base, "skills")
	if err = os.MkdirAll(parent, 0700); err != nil {
		return err
	}
	dir := filepath.Join(parent, "shinphony-task-notify")
	if err = prepareDir(dir); err != nil {
		return err
	}
	path := filepath.Join(dir, "SKILL.md")
	if existing, e := os.ReadFile(path); e == nil {
		if e = privatePath(path, false); e != nil {
			return e
		}
		sum := sha256.Sum256(existing)
		if !bytes.Equal(existing, taskSkill) && !previousTaskSkills[hex.EncodeToString(sum[:])] {
			return errors.New("task_skill_modified_preserved")
		}
		if !bytes.Equal(existing, taskSkill) {
			// An unmodified earlier version of ours: upgrade it in place.
			if e = writePrivateFile(path, taskSkill); e != nil {
				return e
			}
		}
	} else if !os.IsNotExist(e) {
		return e
	} else {
		f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return e
		}
		_, e = f.Write(taskSkill)
		ce := f.Close()
		if e != nil {
			return e
		}
		if ce != nil {
			return ce
		}
	}
	// Separate routing data lets service upgrades keep the user's instructions
	// intact. No shell string or credentials; consumers use an argv invocation.
	client := filepath.Join(dir, "client.json")
	if _, e := os.Lstat(client); e == nil {
		if e = privatePath(client, false); e != nil {
			return e
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	b, _ := json.Marshal(map[string]any{"schema": 1, "executable": exe})
	f, err := os.CreateTemp(dir, ".client-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err != nil {
		return err
	}
	if ce != nil {
		return ce
	}
	return os.Rename(f.Name(), client)
}
