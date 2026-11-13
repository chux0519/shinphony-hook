package notifier

import (
	"strings"
	"testing"
)

func TestQuestionHooksInstalled(t *testing.T) {
	for _, tc := range []struct {
		target  hookTarget
		matcher string
	}{{codexHooks, `"^request_user_input"`}, {claudeHooks, `"AskUserQuestion"`}} {
		out, err := tc.target.propose([]byte(`{}`), "/home/u/.shinphony-agent/shinphony-hook-x")
		if err != nil {
			t.Fatal(err)
		}
		s := string(out)
		i := strings.Index(s, `"PreToolUse"`)
		if i < 0 || !strings.Contains(s[i:], tc.matcher) {
			t.Fatalf("PreToolUse with matcher %s missing:\n%s", tc.matcher, s)
		}
	}
}
