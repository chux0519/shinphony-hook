package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
)

// Notification policy settings, stored as strings in the private state dir and
// re-read for every event so `set` applies without a restart.
type settings struct {
	TurnCompletePush   string // long | all | off
	LongTurnSeconds    int
	SuppressWithoutMux bool
	RateLimitPerMinute int
}

var settingKeys = map[string]struct {
	def   string
	valid func(string) bool
}{
	// Which turn endings get a banner; the others are still sent silently.
	// User policy: a turn ending is not task completion. Keep its Live Activity
	// update silent unless explicitly armed; opt-in all/long remain available.
	"turn-complete-push": {"off", func(v string) bool { return v == "long" || v == "all" || v == "off" }},
	"long-turn-seconds":  {"60", intBetween(0, 86400)},
	// Outside tmux/Zellij/Herdr/screen there is no pane to open: silent push,
	// as in Moshi. Approvals and questions still alert.
	"suppress-push-without-mux": {"on", onOff},
	// Moshi Pro's per-host agent-event budget; the relay enforces the same.
	"rate-limit-per-minute": {"60", intBetween(1, 600)},
}

func onOff(v string) bool { return v == "on" || v == "off" }
func intBetween(lo, hi int) func(string) bool {
	return func(v string) bool { n, err := strconv.Atoi(v); return err == nil && n >= lo && n <= hi }
}

func settingsPath(dir string) string { return filepath.Join(dir, "settings.json") }

func readSettingValues(dir string) (map[string]string, error) {
	values := map[string]string{}
	f, err := os.Open(settingsPath(dir))
	if os.IsNotExist(err) {
		return values, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err = privatePath(settingsPath(dir), false); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(f, 8193))
	if err != nil || len(raw) > 8192 || json.Unmarshal(raw, &values) != nil {
		return nil, errors.New("invalid_settings")
	}
	return values, nil
}

// loadSettings falls back to defaults for missing or invalid values, so a
// damaged file never silences approvals.
func loadSettings(dir string) settings {
	values, _ := readSettingValues(dir)
	get := func(key string) string {
		if v, ok := values[key]; ok && settingKeys[key].valid(v) {
			return v
		}
		return settingKeys[key].def
	}
	long, _ := strconv.Atoi(get("long-turn-seconds"))
	rate, _ := strconv.Atoi(get("rate-limit-per-minute"))
	return settings{
		TurnCompletePush:   get("turn-complete-push"),
		LongTurnSeconds:    long,
		SuppressWithoutMux: get("suppress-push-without-mux") == "on",
		RateLimitPerMinute: rate,
	}
}

func setSetting(dir, key, value string) error {
	spec, ok := settingKeys[key]
	if !ok {
		return errors.New("unknown_setting")
	}
	if !spec.valid(value) {
		return errors.New("invalid_setting_value")
	}
	values, err := readSettingValues(dir)
	if err != nil {
		return err
	}
	values[key] = value
	raw, _ := json.MarshalIndent(values, "", "  ")
	tmp, err := os.CreateTemp(dir, ".settings-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err = tmp.Write(raw); err == nil {
		err = tmp.Sync()
	}
	if ce := tmp.Close(); err == nil {
		err = ce
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), settingsPath(dir))
}

func printSettings(dir string, w io.Writer) error {
	values, err := readSettingValues(dir)
	if err != nil {
		return err
	}
	keys := make([]string, 0, len(settingKeys))
	for k := range settingKeys {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v, set := values[k]
		if !set || !settingKeys[k].valid(v) {
			v = settingKeys[k].def + " (default)"
		}
		fmt.Fprintf(w, "%s = %s\n", k, v)
	}
	return nil
}
