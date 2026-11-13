package main

// `shinphony-hook sessions` lists terminal multiplexer sessions for the app.
//
// The app runs commands over a non-interactive SSH exec channel, which skips
// the login profile: on macOS /opt/homebrew/bin is then missing from PATH and
// a plain `command -v tmux` fails although tmux is installed and running. The
// hook resolves each tool itself (PATH first, then the usual install
// locations), so discovery does not depend on the SSH environment.
//
// Output is the same marker format the app's own POSIX discovery script
// prints, preceded by sessionsHeader, so the app parses both with one parser
// and falls back to its script when the header is missing (old hook).
import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const sessionsHeader = "__SHINPHONY_HOOK_SESSIONS_V1__"

const tmuxSessionFormat = "#{session_name}__SHINPHONY_FIELD__#{session_attached}__SHINPHONY_FIELD__#{session_windows}__SHINPHONY_FIELD__#{session_id}__SHINPHONY_FIELD__#{pid}__SHINPHONY_FIELD__#{session_created}__SHINPHONY_FIELD__#{pane_current_path}"

type sessionManager struct {
	marker string
	tool   string
	args   []string
}

var sessionManagers = []sessionManager{
	// -u: launchd-like environments may set LC_ALL=C; tmux then replaces
	// non-ASCII session names and paths with underscores.
	{"__SHINPHONY_REMOTE_TMUX__", "tmux", []string{"-u", "list-sessions", "-F", tmuxSessionFormat}},
	{"__SHINPHONY_REMOTE_ZELLIJ__", "zellij", []string{"list-sessions"}},
	{"__SHINPHONY_REMOTE_SCREEN__", "screen", []string{"-ls"}},
	{"__SHINPHONY_REMOTE_BYOBU__", "byobu", []string{"list-sessions", "-F", tmuxSessionFormat}},
}

// Install locations that a non-interactive SSH PATH commonly lacks.
func toolDirectories(home string) []string {
	dirs := []string{"/opt/homebrew/bin", "/usr/local/bin", "/opt/local/bin", "/usr/bin", "/bin", "/snap/bin"}
	if home != "" {
		dirs = append(dirs, filepath.Join(home, ".local", "bin"), filepath.Join(home, ".cargo", "bin"), filepath.Join(home, ".nix-profile", "bin"))
	}
	return dirs
}

func findTool(name string, lookPath func(string) (string, error), home string) string {
	if p, err := lookPath(name); err == nil {
		return p
	}
	for _, dir := range toolDirectories(home) {
		p := filepath.Join(dir, name)
		if i, err := os.Stat(p); err == nil && !i.IsDir() && i.Mode()&0o111 != 0 {
			return p
		}
	}
	return ""
}

// runSessionTool returns stdout only. Listing commands exit non-zero when
// there are no sessions (tmux "no server running", screen -ls), which is
// still a valid empty answer.
func runSessionTool(ctx context.Context, path string, args []string) []byte {
	cmd := exec.CommandContext(ctx, path, args...)
	out := &cappedBuffer{limit: 262144}
	cmd.Stdout = out
	cmd.Stdin = nil
	cmd.WaitDelay = 100 * time.Millisecond
	_ = cmd.Run()
	return out.Bytes()
}

func writeSessions(w io.Writer, find func(string) string, run func(context.Context, string, []string) []byte) error {
	var b bytes.Buffer
	b.WriteString(sessionsHeader + "\n")
	for _, m := range sessionManagers {
		b.WriteString(m.marker + "\n")
		path := find(m.tool)
		if path == "" {
			continue
		}
		b.WriteString("__SHINPHONY_AVAILABLE__\n")
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		out := run(ctx, path, m.args)
		cancel()
		b.Write(out)
		if len(out) > 0 && out[len(out)-1] != '\n' {
			b.WriteByte('\n')
		}
	}
	_, err := w.Write(b.Bytes())
	return err
}

func sessionsCLI(w io.Writer) error {
	home, _ := os.UserHomeDir()
	return writeSessions(w, func(name string) string { return findTool(name, exec.LookPath, home) }, runSessionTool)
}
