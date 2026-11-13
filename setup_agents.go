package main

import (
	"errors"
	"net.potafree/shinphony/hook/internal/notifier"
)

var checkCodexHooks = func() (int, int, error) { return codexHookTrust(false) }

func configureSetupAgents(manager notifier.Manager, requested, exe string) error {
	agents := []string{requested}
	if requested == "auto" {
		var err error
		agents, err = manager.DetectedAgents()
		if err != nil {
			return err
		}
		if len(agents) == 0 {
			return errors.New("no_supported_agents")
		}
	}
	// Check all configs first; never blindly replace another tool's hooks.
	for _, agent := range agents {
		if err := manager.Configure(agent, exe, false); err != nil {
			return err
		}
	}
	for _, agent := range agents {
		if err := manager.Configure(agent, exe, true); err != nil {
			return err
		}
		if agent == "codex" {
			if err := installTaskSkill(exe); err != nil {
				return err
			}
		}
	}
	for _, agent := range agents {
		// Codex runs new hooks only after review; say so rather than claim
		// notifications work. An unreachable codex leaves it unknown.
		if agent == "codex" {
			if _, untrusted, err := checkCodexHooks(); err == nil && untrusted > 0 {
				return setupNotice("codex_hooks_need_review")
			}
		}
	}
	return nil
}
