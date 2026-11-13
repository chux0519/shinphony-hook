package notifier

import (
	"os"
	"path/filepath"
)

// Read local state only. Never expose config backups, tokens, command lines or
// task contents, and never label a stored credential as verified APNs delivery.
func (s store) doctor(profile, lane, host string) (map[string]any, error) {
	if !identifier.MatchString(profile) || !identifier.MatchString(host) {
		return nil, errConfig
	}
	if _, e := lanePrefix(lane); e != nil {
		return nil, e
	}
	if e := checkPrivate(s.dir, true); e != nil {
		return nil, e
	}
	result := map[string]any{"schema": 1, "savedPairing": false, "needsRecovery": false, "deliveryVerified": false}
	if c, e := s.load(profile); e == nil {
		if c.Lane != lane || c.Host != host {
			return nil, errConfig
		}
		result["savedPairing"] = true
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	for _, suffix := range []string{".pending", ".lock"} {
		if _, e := os.Lstat(filepath.Join(s.dir, profile+suffix)); e == nil {
			result["needsRecovery"] = true
		}
	}
	for _, agent := range []string{"codex", "codex-hooks", "claude", "dsh"} {
		state := "not_installed"
		rec, e := s.installRecord(agent)
		if e == nil {
			data, present, e := configRead(rec.Path)
			switch {
			case e != nil:
				state = "unreadable"
			case present && digest(data) == rec.After:
				state = "installed"
			case digest(data) == digest(rec.Before) && present == rec.Existed:
				state = "interrupted"
			default:
				state = "changed"
			}
		} else if !os.IsNotExist(e) {
			state = "unreadable"
		}
		result[agent] = state
	}
	return result, nil
}
