package notifier

import (
	"github.com/pelletier/go-toml/v2"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestComputerUseChainRoundTrip(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("macOS callback path")
	}
	callback := "/Users/test user/中文/Codex Computer Use.app/Contents/SharedSupport/SkyComputerUseClient.app/Contents/MacOS/SkyComputerUseClient"
	for _, array := range []string{
		"['" + callback + "', 'turn-ended']",
		"[\n '" + callback + "', # preserve semantics\n 'turn-ended', # ] comment\n]",
	} {
		t.Run(array, func(t *testing.T) {
			s := fixtureStore(t)
			p := filepath.Join(s.dir, "config.toml")
			prefix := "# untouched\nmodel = 'example'\n\"notify\" = "
			suffix := " # keep comment\n[features]\nfoo = true\n"
			original := prefix + array + suffix
			if err := os.WriteFile(p, []byte(original), 0600); err != nil {
				t.Fatal(err)
			}
			for _, version := range []string{"agent-old", "agent-old", "agent-new"} {
				exe := filepath.Join(s.dir, version)
				if err := s.configureCodex(p, exe, true); err != nil {
					t.Fatal(err)
				}
				b, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.HasPrefix(string(b), prefix) || !strings.HasSuffix(string(b), suffix) {
					t.Fatal("unrelated bytes changed")
				}
				var doc struct{ Notify []string }
				if err := toml.Unmarshal(b, &doc); err != nil {
					t.Fatal(err)
				}
				if len(doc.Notify) != 3 || doc.Notify[0] != exe || doc.Notify[1] != "codex-notify-chain" {
					t.Fatalf("bad wrapper: %v", doc.Notify)
				}
				got, err := DecodeComputerUseChain(doc.Notify[2])
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(got, []string{callback, "turn-ended"}) {
					t.Fatal("original argv changed")
				}
			}
			if err := s.uninstallCodex(); err != nil {
				t.Fatal(err)
			}
			b, _ := os.ReadFile(p)
			if string(b) != original {
				t.Fatal("original not restored exactly")
			}
		})
	}
}

func TestComputerUseChainRejectsUnknown(t *testing.T) {
	for _, value := range []string{"[]", "['sh','-c','echo hi']", "['/tmp/SkyComputerUseClient','turn-ended']"} {
		if _, err := proposedCodex([]byte("notify = "+value+"\n"), "/agent"); err == nil {
			t.Fatalf("accepted %s", value)
		}
	}
	for _, encoded := range []string{"!", "W10", strings.Repeat("a", 16385)} {
		if _, err := DecodeComputerUseChain(encoded); err == nil {
			t.Fatal("accepted invalid chain")
		}
	}
}
