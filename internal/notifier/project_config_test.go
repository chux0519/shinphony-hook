package notifier

import (
	"bytes"
	"testing"
)

func TestCodexShinphonyProjectIsNotAnIntegration(t *testing.T) {
	before := []byte("# Work on Shinphony\n[projects.\"/home/test/Shinphony\"]\ntrust_level = \"trusted\"\n")
	after, err := proposedCodex(before, "/private/agent")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(after, before) {
		t.Fatal("project configuration changed")
	}
	if _, err = proposedCodex([]byte("notify = [\"other-tool\"]\n"), "/private/agent"); err == nil {
		t.Fatal("real conflict overwritten")
	}
}
