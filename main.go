package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net.potafree/shinphony/hook/internal/notifier"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const version = "0.1.0-dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "task-intent" {
		output, err := taskIntentOutput(os.Args[2:])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Print(output)
		return
	}

	if len(os.Args) > 1 && (os.Args[1] == "codex-notify-all" || os.Args[1] == "codex-notify-chain" || os.Args[1] == "claude-hook-all" || os.Args[1] == "dsh-hook-all" || os.Args[1] == "codex-hook-all") {
		hookCLI(os.Args[1], os.Args[2:])
		return
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	if err := privateUmask(); err != nil {
		return errors.New("private_creation_policy_failed")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return errors.New("home_unavailable")
	}
	flags := flag.NewFlagSet(commandName, flag.ContinueOnError)
	dir := flags.String("state-dir", filepath.Join(home, stateDirectoryName), "private local state directory")
	creds := flags.String("credentials-dir", filepath.Join(home, credentialsDirectoryName), "existing private pairing directory")
	if err = flags.Parse(os.Args[1:]); err != nil {
		return err
	}
	args := flags.Args()
	if sshPairSelected(args) {
		return sshPairCLI(args[1:], os.Stdin, os.Stdout)
	}
	if len(args) > 0 && args[0] == "keys" {
		return keysCLI(args[1:], os.Stdin, os.Stdout)
	}
	if !filepath.IsAbs(*creds) {
		return errors.New("absolute_credentials_path_required")
	}
	if len(args) == 3 && args[0] == "set" {
		if err = prepareDir(*dir); err != nil {
			return errors.New("unsafe_state_directory")
		}
		return setSetting(*dir, args[1], args[2])
	}
	if len(args) >= 1 && args[0] == "notify" {
		os.Exit(notifyCLI(*dir, args[1:], os.Stdin, os.Stderr))
	}
	if len(args) == 1 && args[0] == "get" {
		return printSettings(*dir, os.Stdout)
	}
	if len(args) == 1 && (args[0] == "codex-hooks-status" || args[0] == "trust-codex-hooks") {
		trusted, untrusted, e := codexHookTrust(args[0] == "trust-codex-hooks")
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]int{"trusted": trusted, "untrusted": untrusted})
	}
	// debug-hc-capture is a read-only developer command: it takes an address and
	// an optional event status, so it is the only form with two or three
	// arguments after the command.
	if len(args) < 1 || len(args) > 3 {
		return errors.New("usage: " + commandName + " [flags] init|install-service|uninstall-service|serve|status|doctor|event|sessions|version")
	}
	if args[0] == "debug-hc-capture" {
		if len(args) < 2 {
			return errors.New("usage: " + commandName + " debug-hc-capture <address> [completed|failed|attention]")
		}
		// No state directory and no daemon: reads the local core only.
		status := "completed"
		if len(args) == 3 {
			status = args[2]
		}
		return debugHcCapture(os.Stdout, args[1], status)
	}
	if len(args) > 2 || (len(args) == 2 && args[0] != "setup-status" && args[0] != "setup-latest" && args[0] != "attach-event" && args[0] != "attach-recent" && args[0] != "resolve-event") {
		return errors.New("usage: " + commandName + " [flags] init|install-service|uninstall-service|serve|status|doctor|event|sessions|version")
	}
	if args[0] == "version" {
		fmt.Println(version)
		return nil
	}
	if args[0] == "sessions" {
		return sessionsCLI(os.Stdout)
	}
	if args[0] == "diagnose-codex" {
		return json.NewEncoder(os.Stdout).Encode(diagnoseCodex())
	}
	if args[0] == "build-info" {
		return updateBuildInfo()
	}
	if args[0] == "uninstall-codex-hook" {
		return (notifier.Manager{Directory: *creds}).Uninstall("codex")
	}
	if args[0] == "refresh-integrations" {
		exe, e := serviceExecutable(*dir)
		if e != nil {
			return e
		}
		m := notifier.Manager{Directory: *creds}
		agents, e := m.InstalledAgents()
		if e != nil {
			return e
		}
		for _, agent := range agents {
			if e = m.Configure(agent, exe, true); e != nil {
				return e
			}
			if agent == "codex" {
				if e = installTaskSkill(exe); e != nil {
					return e
				}
			}
		}
		return nil
	}
	if err = prepareDir(*dir); err != nil {
		return errors.New("unsafe_state_directory")
	}
	if args[0] == "task-event" {
		return explicitTaskEvent(*dir, os.Stdin)
	}
	if args[0] == "check-update" {
		return checkUpdate(*dir, *creds)
	}
	if args[0] == "configure-updates" {
		return configureUpdates(*dir, os.Stdin)
	}
	if args[0] == "start-update" {
		return startUpdate(*dir, *creds)
	}
	if args[0] == "attach-event" && len(args) == 2 {
		return attachContext(*dir, args[1])
	}
	if args[0] == "attach-recent" && len(args) == 2 {
		return attachRecent(*dir, args[1])
	}
	if args[0] == "resolve-event" && len(args) == 2 {
		c, e := fetchSnapshot(*dir, args[1])
		if e != nil {
			return e
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		out, e := resolveHcEvent(ctx, c)
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(out)
	}
	if args[0] == "init" {
		fmt.Println(`{"initialized":true}`)
		return nil
	}
	if args[0] == "install-service" {
		return installService(*dir, *creds)
	}
	if args[0] == "ensure-service" {
		return ensureService(*dir, *creds)
	}
	if args[0] == "apply-update" {
		return ensureServiceMode(*dir, *creds, true)
	}
	if args[0] == "uninstall-service" {
		return uninstallRequested(*dir)
	}
	if args[0] == "supervise" {
		return supervise(*dir, *creds)
	}
	if args[0] == "serve" {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect_refused") }}
		return serve(ctx, *dir, deliver(*creds, client), *creds)
	}
	endpoint := "/v1/status"
	if args[0] == "doctor" {
		endpoint = "/v1/doctor"
	}
	method := "GET"
	var body io.Reader
	if args[0] == "setup-status" && len(args) == 2 && identifier.MatchString(args[1]) {
		endpoint = "/v1/setup/" + args[1]
	}
	if args[0] == "setup-latest" && len(args) == 2 && identifier.MatchString(args[1]) {
		endpoint = "/v1/setup-latest/" + args[1]
	}
	if args[0] == "event" {
		endpoint = "/v1/events"
		method = "POST"
		body = io.LimitReader(os.Stdin, 4097)
	} else if args[0] == "focus-event" || args[0] == "workspace" || args[0] == "pair" || args[0] == "setup" || args[0] == "pairing-status" || args[0] == "reset-profile" || args[0] == "presence" || args[0] == "hc-presence" {
		endpoint = "/v1/" + args[0]
		method = "POST"
		body = io.LimitReader(os.Stdin, 12289)
	} else if args[0] != "status" && args[0] != "doctor" && !((args[0] == "setup-status" || args[0] == "setup-latest") && len(args) == 2 && identifier.MatchString(args[1])) {
		return errors.New("unknown_command")
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return dialLocal(ctx, *dir)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 12 * time.Second}
	req, _ := http.NewRequest(method, "http://localhost"+endpoint, body)
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("service_unavailable")
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8193))
	if err != nil || len(data) > 8192 {
		return errors.New("invalid_service_response")
	}
	fmt.Println(string(data))
	if resp.StatusCode != 200 {
		if code := strings.TrimSpace(string(data)); identifier.MatchString(code) {
			return errors.New(code)
		}
		return errors.New("request_rejected")
	}
	return nil
}
func serve(ctx context.Context, dir string, send sender, credentialDirs ...string) error {
	unlock, err := lockDir(dir)
	if err != nil {
		return err
	}
	defer unlock()
	dbpath := filepath.Join(dir, "state.db")
	for _, p := range []string{dbpath, dbpath + "-wal", dbpath + "-shm"} {
		if _, err = os.Lstat(p); err == nil {
			if err = privatePath(p, false); err != nil {
				return err
			}
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	q, err := openQueue(dbpath)
	if err != nil {
		return safeDBError(err)
	}
	defer q.db.Close()
	if err = q.initJobs(); err != nil {
		return safeDBError(err)
	}
	jobCtx, stopJobs := context.WithCancel(ctx)
	defer stopJobs()
	var jobDone chan error
	if len(credentialDirs) > 0 {
		exe, e := serviceExecutable(dir)
		if e != nil {
			return e
		}
		jobDone = make(chan error, 1)
		go func(ch chan error) { ch <- jobsWorker(jobCtx, q, notifier.Manager{Directory: credentialDirs[0]}, exe) }(jobDone)
		defer func() {
			stopJobs()
			if jobDone != nil {
				<-jobDone
			}
		}()
	}
	ln, err := listenLocal(dir)
	if err != nil {
		return errors.New("listen_failed")
	}
	defer ln.Close()
	wake := make(chan struct{}, 1)
	mux := http.NewServeMux()
	q.registerContexts(mux)
	q.registerPresence(mux)
	if len(credentialDirs) > 0 {
		manager := notifier.Manager{Directory: credentialDirs[0]}
		registerSetup(mux, q, manager)
		turns := newTracker()
		mux.HandleFunc("POST /v1/agent-events", func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, 4096)
			d := json.NewDecoder(r.Body)
			d.DisallowUnknownFields()
			var e agentEvent
			if d.Decode(&e) != nil || d.Decode(new(any)) != io.EOF || !e.valid() {
				http.Error(w, "invalid_event", 400)
				return
			}
			dec := turns.decide(e, loadSettings(dir), time.Now())
			if dec.Status == "" {
				json.NewEncoder(w).Encode(map[string]any{"queued": false, "reason": dec.Reason})
				return
			}
			// hc always; a tmux pane for questions, so tapping the notification
			// attaches to Codex's own pane and the phone can answer there.
			question := dec.Details != nil && dec.Details.Category == "question"
			if e.Source != nil && (e.Source.HcAddress != "" || e.Source.HcSocket != "" || (question && e.Source.Tmux != "" && e.Source.Pane != "")) {
				c := captureContext(r.Context(), e.Source, dec.ID, dir)
				if c != nil {
					c.Preview = cleanText(e.Title, 700)
					if question && dec.Details.Body != "" {
						c.Preview = cleanText(dec.Details.Title+"\n"+dec.Details.Body, 700)
					}
					if err := q.saveContext(c, time.Now().Unix()); err != nil {
						http.Error(w, "context_storage_unavailable", 503)
						return
					}
				}
			}
			payload, _ := json.Marshal(dec.Details)
			q.profileMu.Lock()
			defer q.profileMu.Unlock()
			profiles, err := manager.Profiles()
			if err != nil {
				http.Error(w, "pairings_unavailable", 503)
				return
			}
			for _, profile := range profiles {
				if _, err = q.enqueueWith(Event{profile, dec.ID, dec.Status}, string(payload), time.Now().Unix()); err != nil {
					http.Error(w, enqueueErrorCode(err), 409)
					return
				}
			}
			select {
			case wake <- struct{}{}:
			default:
			}
			json.NewEncoder(w).Encode(map[string]any{"queued": true, "destinations": len(profiles), "visibility": dec.Details.Visibility})
		})
		mux.HandleFunc("POST /v1/notify", func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, 4096)
			d := json.NewDecoder(r.Body)
			d.DisallowUnknownFields()
			var n notifyRequest
			if d.Decode(&n) != nil || d.Decode(new(any)) != io.EOF || !n.valid() {
				http.Error(w, "invalid_notification", 400)
				return
			}
			if !turns.allow(loadSettings(dir).RateLimitPerMinute, time.Now()) {
				json.NewEncoder(w).Encode(map[string]any{"queued": false, "reason": "rate_limited"})
				return
			}
			status, details := n.details()
			payload, _ := json.Marshal(details)
			q.profileMu.Lock()
			defer q.profileMu.Unlock()
			profiles, err := manager.Profiles()
			if err != nil || len(profiles) == 0 {
				json.NewEncoder(w).Encode(map[string]any{"queued": false, "reason": "not_paired"})
				return
			}
			for _, profile := range profiles {
				if _, err = q.enqueueWith(Event{profile, n.EventID, status}, string(payload), time.Now().Unix()); err != nil {
					http.Error(w, enqueueErrorCode(err), 409)
					return
				}
			}
			select {
			case wake <- struct{}{}:
			default:
			}
			json.NewEncoder(w).Encode(map[string]any{"queued": true, "destinations": len(profiles)})
		})
		mux.HandleFunc("GET /v1/notify/{id}", func(w http.ResponseWriter, r *http.Request) {
			id := r.PathValue("id")
			if !identifier.MatchString(id) {
				http.Error(w, "invalid_event", 400)
				return
			}
			state, code, err := q.eventState(id)
			if err != nil {
				http.Error(w, "not_found", 404)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"state": state, "code": code})
		})
		mux.HandleFunc("POST /v1/hooks", func(w http.ResponseWriter, r *http.Request) {
			q.profileMu.Lock()
			defer q.profileMu.Unlock()
			r.Body = http.MaxBytesReader(w, r.Body, 4096)
			d := json.NewDecoder(r.Body)
			d.DisallowUnknownFields()
			var e hookEvent
			if d.Decode(&e) != nil || d.Decode(new(any)) != io.EOF || !(Event{"check", e.ID, e.Status}).valid() {
				http.Error(w, "invalid_event", 400)
				return
			}
			// Old immutable hook binaries may still run in existing Codex sessions.
			// A turn/Stop callback is not evidence that the user's task is done.
			if e.Status == "completed" && e.Trigger != "explicit-task" {
				json.NewEncoder(w).Encode(map[string]any{"queued": false, "reason": "turn_is_not_task"})
				return
			}
			profiles, err := manager.Profiles()
			if err != nil {
				http.Error(w, "pairings_unavailable", 503)
				return
			}
			c := captureContext(r.Context(), e.Source, e.ID, dir)
			if c != nil {
				if err = q.saveContext(c, time.Now().Unix()); err != nil {
					http.Error(w, "context_storage_unavailable", 503)
					return
				}
			}
			for _, profile := range profiles {
				if _, err = q.enqueue(Event{profile, e.ID, e.Status}, time.Now().Unix()); err != nil {
					http.Error(w, enqueueErrorCode(err), 409)
					return
				}
			}
			select {
			case wake <- struct{}{}:
			default:
			}
			location := "unavailable"
			if c != nil {
				location = "resolved"
			}
			json.NewEncoder(w).Encode(map[string]any{"queued": true, "destinations": len(profiles), "contextStatus": location})
		})
	}
	mux.HandleFunc("GET /v1/doctor", func(w http.ResponseWriter, r *http.Request) {
		entries, err := q.diagnostics()
		if err != nil {
			http.Error(w, "storage_unavailable", 503)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"schema": 1, "version": version, "service": "running", "recent": entries, "deliveryVerified": false, "codexBackend": diagnoseCodex()})
	})
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		counts, err := q.counts()
		if err != nil {
			http.Error(w, "storage_unavailable", 503)
			return
		}
		exe, _ := executablePath()
		creds := ""
		if len(credentialDirs) > 0 {
			creds = credentialDirs[0]
		}
		json.NewEncoder(w).Encode(map[string]any{"schema": 1, "version": version, "releaseSequence": sequence(), "apiVersion": 2, "setupJobs": len(credentialDirs) > 0, "service": "running", "queue": counts, "deliveryVerified": false, "executable": exe, "credentialsDirectory": creds, "update": updateProgress(dir)})
	})
	mux.HandleFunc("POST /v1/events", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		var e Event
		if dec.Decode(&e) != nil || dec.Decode(new(any)) != io.EOF || !e.valid() {
			http.Error(w, "invalid_event", 400)
			return
		}
		inserted, err := q.enqueue(e, time.Now().Unix())
		if err != nil {
			http.Error(w, enqueueErrorCode(err), 409)
			return
		}
		select {
		case wake <- struct{}{}:
		default:
		}
		json.NewEncoder(w).Encode(map[string]any{"queued": true, "duplicate": !inserted})
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 4096}
	serverErrors := make(chan error, 1)
	go func() { serverErrors <- server.Serve(ln) }()
	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- worker(workerCtx, q, send, wake) }()
	socketGone := watchSocket(workerCtx, dir)
	var outcome error
	select {
	case <-ctx.Done():
	case outcome = <-socketGone:
	case outcome = <-serverErrors:
	case outcome = <-done:
		done = nil
	case outcome = <-jobDone:
		jobDone = nil
	}
	cancel()
	shutdown, c := context.WithTimeout(context.Background(), 4*time.Second)
	defer c()
	server.Shutdown(shutdown)
	if done != nil {
		<-done
	}
	if errors.Is(outcome, http.ErrServerClosed) {
		return nil
	}
	return outcome
}
func worker(ctx context.Context, q *queue, send sender, wake <-chan struct{}) error {
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	maintenance := time.NewTicker(time.Hour)
	defer maintenance.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		now := time.Now().Unix()
		i, err := q.next(now)
		if err == sql.ErrNoRows {
			select {
			case <-ctx.Done():
				return nil
			case <-tick.C:
			case <-wake:
			case <-maintenance.C:
				if err = q.maintain(time.Now().Unix()); err != nil {
					return safeDBError(err)
				}
			}
			continue
		}
		if err != nil {
			return safeDBError(err)
		}
		if i.Attempts >= 8 {
			if err = q.finish(i, now, result{Code: "attempts_exhausted"}); err != nil {
				return safeDBError(err)
			}
			continue
		}
		if err = q.reserve(i, now); err != nil {
			return safeDBError(err)
		}
		call, cancel := context.WithTimeout(ctx, 5*time.Second)
		q.profileMu.Lock()
		var exists int
		checkErr := q.db.QueryRow("SELECT count(*) FROM outbox WHERE profile=? AND event_id=?", i.Profile, i.ID).Scan(&exists)
		r := result{Code: "pairing_reset"}
		if checkErr == nil && exists > 0 {
			c := q.contextForEvent(i.ID)
			if c != nil {
				call = context.WithValue(call, taskContextKey{}, c.taskContext)
			}
			if i.Payload != "" {
				call = context.WithValue(call, agentDetailsKey{}, json.RawMessage(i.Payload))
			}
			if c != nil && q.activelyViewing(call, i.Profile, c) {
				r = result{Code: "actively_viewing"}
			} else {
				r = send(call, i.Event)
			}
		}
		q.profileMu.Unlock()
		cancel()
		if r.Retry && r.After <= 0 {
			r.After = time.Duration(1<<min(i.Attempts+1, 10))*time.Second + time.Duration(rand.Intn(1000))*time.Millisecond
		}
		if err = q.finish(i, time.Now().Unix(), r); err != nil {
			return safeDBError(err)
		}
		// Bound throughput, including a backlog of permanently invalid credentials.
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(100 * time.Millisecond):
		}
	}
}
