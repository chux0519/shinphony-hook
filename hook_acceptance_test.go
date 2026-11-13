package main

import (
	"context"
	"strings"
	"testing"
)

func TestHookAcceptanceCompatibilityAndFeedback(t *testing.T) {
	exe := "/private/bin/shinphony-hook-" + strings.Repeat("a", 64)
	output, _ := taskIntentOutput([]string{"task", "completed"})
	raw := intentHook(taskIntentCommand(exe, "task", "completed", false), output)
	for _, tc := range []struct{ body, want, avoid string }{
		{`{"queued":true,"contextStatus":"resolved","destinations":0}`, "terminal location resolved; no paired phone destinations", "unavailable"},
		{`{"queued":true,"contextStatus":"unavailable","destinations":1}`, "terminal location unavailable", "resolved"},
		{`{"queued":true,"destinations":0}`, "terminal location unknown; no paired phone destinations", "resolved"},
		{`{"queued":false}`, "not accepted", "accepted locally"},
		{`{"contextStatus":"/private/secret","destinations":-1}`, "local acceptance unverified", "/private/secret"},
		{`malformed`, "local acceptance unverified", "accepted locally"},
		{``, "local acceptance unverified", "accepted locally"},
		{`{"queued":true`, "local acceptance unverified", "accepted locally"},
		{`{}`, "local acceptance unverified", "accepted locally"},
		{strings.Repeat(" ", 4097) + `{"queued":true}`, "local acceptance unverified", "accepted locally"},
	} {
		t.Run(tc.body, func(t *testing.T) {
			feedback := forwardTaskIntent(context.Background(), raw, exe, 42, func(k string) string {
				if k == "HC_TERMINAL_ID" {
					return "t1"
				}
				return ""
			}, func(context.Context, int) (string, string) { t.Fatal("hc fallback"); return "", "" }, func(hookEvent) (hookAcceptance, error) { return decodeHookAcceptance([]byte(tc.body)), nil })
			message := feedback["systemMessage"].(string)
			if !strings.Contains(message, tc.want) || strings.Contains(message, tc.avoid) || !strings.Contains(message, "phone delivery unverified") {
				t.Fatal(message)
			}
		})
	}
}
