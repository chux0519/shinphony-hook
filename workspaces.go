package main

// Workspace paths stay on the host. They never enter the APNs relay.
import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type workspaceState struct {
	ID          string `json:"id"`
	Multiplexer string `json:"multiplexer"`
	Directory   string `json:"directory"`
	Files       string `json:"files,omitempty"`
	Git         string `json:"git,omitempty"`
}
type workspaceRequest struct {
	KnownID    string  `json:"knownId,omitempty"`
	RecoverGit bool    `json:"recoverGit,omitempty"`
	TTY        string  `json:"tty"`
	ID         string  `json:"id"`
	Files      *string `json:"files,omitempty"`
	Git        *string `json:"git,omitempty"`
}

func workspaceID(s *recentSession) string {
	digest := sha256.Sum256([]byte(strings.Join([]string{"tmux", s.Socket, s.ServerPID, s.ServerStart, s.Session}, "\x00")))
	return hex.EncodeToString(digest[:])
}
func validWorkspacePath(s string) bool {
	return len(s) <= 4096 && filepath.IsAbs(s) && !strings.ContainsAny(s, "\x00\r\n")
}
func resolveWorkspace(ctx context.Context, tty string) (*workspaceState, error) {
	if !strings.HasPrefix(tty, "/dev/") || len(tty) > 128 || strings.ContainsAny(tty, "\x00\r\n\t") {
		return nil, errors.New("invalid_tty")
	}
	raw, err := tmuxOutput(ctx, "list-clients", "-F", "#{client_tty}\t#{socket_path}\t#{pid}\t#{session_id}\t#{window_id}\t#{pane_id}\t#{pane_pid}")
	if err != nil {
		return nil, err
	}
	s := parseRecent(raw, tty)
	if s == nil {
		return nil, errors.New("workspace_unavailable")
	}
	pid, _ := strconv.Atoi(s.ServerPID)
	s.ServerStart = processStart(ctx, pid)
	if s.ServerStart == "" {
		return nil, errors.New("workspace_unavailable")
	}
	cwd, err := tmuxOutput(ctx, "-S", s.Socket, "display-message", "-p", "-t", s.Session+":"+s.Window+"."+s.Pane, "#{pane_current_path}")
	cwd = strings.TrimSuffix(cwd, "\n")
	if err != nil || !validWorkspacePath(cwd) {
		return nil, errors.New("workspace_unavailable")
	}
	return &workspaceState{ID: workspaceID(s), Multiplexer: "tmux", Directory: cwd}, nil
}

func (q *queue) workspace(w http.ResponseWriter, r *http.Request, resolve func(context.Context, string) (*workspaceState, error)) {
	var input workspaceRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 12288))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil {
		http.Error(w, "invalid_request", 400)
		return
	}
	if (input.Files != nil && !validWorkspacePath(*input.Files)) || (input.Git != nil && !validWorkspacePath(*input.Git)) {
		http.Error(w, "invalid_path", 400)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	state, err := resolve(ctx, input.TTY)
	if err != nil {
		http.Error(w, "workspace_unavailable", 404)
		return
	}
	if (input.ID != "" && input.ID != state.ID) || ((input.Files != nil || input.Git != nil) && input.ID == "") {
		http.Error(w, "workspace_changed", 409)
		return
	}
	// Atomic field patches avoid a Files save overwriting a concurrent Git save.
	if input.Files != nil || input.Git != nil {
		_, err = q.db.ExecContext(ctx, `INSERT INTO workspace_paths(id,files,git,updated) VALUES(?,COALESCE(?,''),COALESCE(?,''),?) ON CONFLICT(id) DO UPDATE SET files=COALESCE(?,files),git=COALESCE(?,git),updated=excluded.updated`, state.ID, input.Files, input.Git, time.Now().Unix(), input.Files, input.Git)
		if err != nil {
			http.Error(w, "save_failed", 500)
			return
		}
		q.db.ExecContext(ctx, "DELETE FROM workspace_paths WHERE id NOT IN (SELECT id FROM workspace_paths ORDER BY updated DESC LIMIT 512)")
	}
	err = q.db.QueryRowContext(ctx, "SELECT files,git FROM workspace_paths WHERE id=?", state.ID).Scan(&state.Files, &state.Git)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "read_failed", 500)
		return
	}
	if input.RecoverGit {
		state.Git = discoverWorkspaceGit(ctx, state.Git, state.Directory)
	} else if state.Git == "" && input.KnownID != state.ID {
		state.Git = discoverWorkspaceGit(ctx, "", state.Directory)
	}
	// No stored paths means a new workspace. The App uses the pane cwd initially.
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(state)
}

func discoverWorkspaceGit(ctx context.Context, saved, cwd string) string {
	paths := []string{}
	for i := 0; validWorkspacePath(saved) && i < 12; i++ {
		paths = append(paths, saved)
		parent := filepath.Dir(saved)
		if parent == saved {
			break
		}
		saved = parent
	}
	paths = append(paths, cwd)
	for _, path := range paths {
		if ctx.Err() != nil || !validWorkspacePath(path) {
			continue
		}
		gitCtx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
		root, err := exec.CommandContext(gitCtx, "git", "-C", path, "rev-parse", "--show-toplevel").Output()
		cancel()
		value := strings.TrimSuffix(string(root), "\n")
		if err == nil && validWorkspacePath(value) {
			return value
		}
	}
	return ""
}
func (q *queue) registerWorkspaces(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/workspace", func(w http.ResponseWriter, r *http.Request) { q.workspace(w, r, resolveWorkspace) })
}
