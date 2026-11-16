package main

// Inventory publishing (design: ShinphonyApp docs/design/agent_first_layout_
// 20261115.md §1, §4). H1 built the inventory in the daemon; without an SSH
// connection the App never saw it. The daemon now seals the same document to
// every private pairing and PUTs the opaque envelope to the relay, which keeps
// the latest blob per (device, host).
//
// The job is deliberately dull: a poll loop that builds the inventory once per
// tick, seals it per pairing and sends it only when something changed. It has
// its own client, its own goroutine and its own backoff, so a relay that is
// slow or down can never touch notification delivery.
import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// The relay refuses a larger sealed blob; trimming drops rows until it fits
	// (the inventory already caps at 200 rows).
	inventoryEnvelopeMaxBytes = 24 * 1024
	// A rebuild requested by an agent event lands this long after the last
	// event, so a burst of hook calls is one listing and one blob.
	inventoryPublishDebounce = 3 * time.Second
	// Never more than one publish per device in this window, whatever happens.
	inventoryPublishInterval = 10 * time.Second
	// Mux-only changes (a new tmux window, a renamed terminal) have no event to
	// wake the daemon: one slow poll picks them up, and only while a private
	// pairing exists.
	inventoryPublishPoll = 30 * time.Second
	// While nothing changes, one blob every ten minutes keeps the phone's view
	// visibly fresh.
	inventoryPublishHeartbeat = 10 * time.Minute
	inventoryPublishBackoff   = 10 * time.Second
	inventoryPublishMaxRetry  = 10 * time.Minute
	// The loop's cadence: no listings, only timers and a cheap pairing read, so
	// one second is free and makes the debounce exact.
	inventoryPublishTick = time.Second
	// A pairing directory is small; this is the same bound Profiles() uses.
	maxInventoryTargets = 100
)

// inventoryRelayBase is the relay the daemon publishes inventory to. It is a
// variable only so the tests can point it at their own server; empty turns the
// job off (the test binary must never reach the real relay).
var inventoryRelayBase = "https://notify.potafree.net"

// inventoryTarget is one paired phone that may receive a blob: the lane's
// prefix, the host credential the relay checks, the opaque hostRef and the
// phone's key. A pairing without a key is not a target: plaintext never leaves.
type inventoryTarget struct {
	Profile  string
	Lane     string
	HostRef  string
	Token    string
	PhonePub []byte
}

// inventoryPublishState is the per-device scheduling state: what the phone last
// received and when the next try may happen.
type inventoryPublishState struct {
	seen      string    // fingerprint of the content last published
	published time.Time // last successful publish
	retryAt   time.Time // not before this, after a failure
	failures  int
}

// inventoryPublisher is the whole job, with every dependency injectable so the
// timing tests need neither a real clock nor a real relay.
//
// The listing work is event-driven: an agent event or a pairing change arms one
// debounced rebuild, and a slow poll covers changes nothing reports (a new tmux
// window). Quiet costs one pairing read per tick and no listings at all.
type inventoryPublisher struct {
	Now     func() time.Time
	Build   func(context.Context) inventory
	Targets func() ([]inventoryTarget, error)
	Seal    func(io.Reader, []byte, string, []byte) (e2eEnvelope, error)
	Send    func(context.Context, inventoryTarget, e2eEnvelope) (int, error)
	Tick    time.Duration
	states  map[string]*inventoryPublishState
	// wake carries the non-blocking signal of the event path; rebuildAt is
	// when the debounced rebuild is due, pollAt the next slow mux poll.
	wake      chan struct{}
	rebuildAt time.Time
	pollAt    time.Time
	// built is the document the last rebuild produced and its fingerprint. A
	// publish reuses it: two devices receive the same rows, sealed separately.
	built       bool
	builtDoc    inventory
	fingerprint string
}

func newInventoryPublisher(creds string, build func(context.Context) inventory) *inventoryPublisher {
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirect_refused")
		},
	}
	return &inventoryPublisher{
		Now:     time.Now,
		Build:   build,
		Targets: func() ([]inventoryTarget, error) { return inventoryTargets(creds) },
		Seal:    e2eSeal,
		Send:    inventorySender(client, inventoryRelayBase),
		Tick:    inventoryPublishTick,
		states:  map[string]*inventoryPublishState{},
		wake:    make(chan struct{}, 1),
	}
}

// Wake asks for a rebuild after the debounce. The event path calls it and never
// waits for the inventory: one pending request is all a burst deserves, so a
// full channel drops the signal.
func (p *inventoryPublisher) Wake() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

// scheduleRebuild arms the next event-driven rebuild. A later event moves it,
// so a burst of hook calls costs one listing at its end.
func (p *inventoryPublisher) scheduleRebuild(now time.Time) {
	p.rebuildAt = now.Add(inventoryPublishDebounce)
}

// run is the job's only goroutine. It never returns an error: a bad tick is a
// skipped tick, and the next one tries again.
func (p *inventoryPublisher) run(ctx context.Context) {
	tick := p.Tick
	if tick <= 0 {
		tick = inventoryPublishTick
	}
	timer := time.NewTicker(tick)
	defer timer.Stop()
	p.step(ctx, p.Now())
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.wake:
			p.scheduleRebuild(p.Now())
		case <-timer.C:
		}
		p.step(ctx, p.Now())
	}
}

// step is one scheduler pass: maybe rebuild, then decide per device. A tick
// with no private pairing does no work at all (not even a listing), and one
// that cannot read the pairing directory publishes to nobody rather than to a
// guess.
func (p *inventoryPublisher) step(ctx context.Context, now time.Time) {
	targets, err := p.Targets()
	if err != nil {
		return
	}
	present := make(map[string]bool, len(targets))
	for _, target := range targets {
		present[target.Profile] = true
	}
	// Unpairing or a revoke stops publishing at once, and takes the hash with
	// it: re-pairing the same phone must publish the same inventory again.
	for profile := range p.states {
		if !present[profile] {
			delete(p.states, profile)
		}
	}
	if len(targets) == 0 {
		// No private pairing: no rebuild and no poll. A new pairing rebuilds at
		// once, so nothing has to be kept warm for it.
		p.rebuildAt, p.pollAt, p.built = time.Time{}, time.Time{}, false
		return
	}
	fresh := false
	for _, target := range targets {
		if _, ok := p.states[target.Profile]; !ok {
			p.states[target.Profile] = &inventoryPublishState{}
			fresh = true
		}
	}
	// The rebuild is the expensive part and only runs when something asked for
	// it; publishing is then evaluated every tick, so a change held back by the
	// ten-second floor or a backoff goes out as soon as it may.
	p.rebuild(ctx, now, fresh)
	if !p.built {
		return
	}
	p.publish(ctx, targets, now)
}

// rebuild decides whether this tick lists anything: a new pairing, the first
// build, a debounced event, the slow poll, or a heartbeat (which must carry a
// current generatedAt, not one from hours ago).
func (p *inventoryPublisher) rebuild(ctx context.Context, now time.Time, fresh bool) {
	due := fresh || !p.built
	if !p.rebuildAt.IsZero() && !now.Before(p.rebuildAt) {
		due = true
	}
	if p.pollAt.IsZero() || !now.Before(p.pollAt) {
		due = true
	}
	for _, st := range p.states {
		if !st.published.IsZero() && now.Sub(st.published) >= inventoryPublishHeartbeat {
			due = true
		}
	}
	if !due {
		return
	}
	p.builtDoc = p.Build(ctx)
	p.fingerprint, p.built = inventoryFingerprint(p.builtDoc), true
	p.rebuildAt, p.pollAt = time.Time{}, now.Add(inventoryPublishPoll)
}

// publish sends the built document to every device that needs it. The debounce
// already happened in the rebuild, so a change is published as soon as the
// ten-second floor allows.
func (p *inventoryPublisher) publish(ctx context.Context, targets []inventoryTarget, now time.Time) {
	for _, target := range targets {
		st := p.states[target.Profile]
		if st == nil || now.Before(st.retryAt) {
			continue
		}
		changed := st.seen != p.fingerprint
		intervalOK := st.published.IsZero() || now.Sub(st.published) >= inventoryPublishInterval
		heartbeat := !changed && !st.published.IsZero() && now.Sub(st.published) >= inventoryPublishHeartbeat
		if !(changed && intervalOK) && !heartbeat {
			continue
		}
		envelope, err := sealInventory(func(raw []byte) (e2eEnvelope, error) {
			return p.Seal(randomReader, target.PhonePub, target.HostRef, raw)
		}, p.builtDoc)
		if err != nil {
			st.fail(now)
			continue
		}
		status, err := p.Send(ctx, target, envelope)
		if err == nil && (status == http.StatusOK || status == http.StatusAccepted) {
			st.seen, st.published, st.failures, st.retryAt = p.fingerprint, now, 0, time.Time{}
			continue
		}
		st.fail(now)
	}
}

// fail backs off: a relay that is down is retried, never hammered.
func (st *inventoryPublishState) fail(now time.Time) {
	st.failures++
	backoff := inventoryPublishBackoff << uint(min(st.failures-1, 6))
	if backoff > inventoryPublishMaxRetry {
		backoff = inventoryPublishMaxRetry
	}
	st.retryAt = now.Add(backoff)
}

// inventoryFingerprint hashes what the phone would see. `generatedAt` and every
// row's `since` move on each build, so they are not a change; the row set,
// titles, states and directories are.
func inventoryFingerprint(inv inventory) string {
	normalized := inv
	normalized.GeneratedAt = 0
	normalized.Conversations = append([]inventoryConversation(nil), inv.Conversations...)
	for i := range normalized.Conversations {
		normalized.Conversations[i].Since = 0
	}
	raw, err := json.Marshal(normalized)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// sealInventory seals the document, trimming it until the sealed blob fits the
// relay's bound. A document that fits is sent untouched; the caller's copy is
// never mutated, so every pairing gets the same rows sealed to its own key.
func sealInventory(seal func([]byte) (e2eEnvelope, error), inv inventory) (e2eEnvelope, error) {
	doc := inv
	doc.Conversations = append([]inventoryConversation(nil), inv.Conversations...)
	for {
		raw, err := json.Marshal(doc)
		if err != nil {
			return e2eEnvelope{}, errors.New("inventory_invalid")
		}
		envelope, err := seal(raw)
		if err != nil {
			return e2eEnvelope{}, err
		}
		body, err := json.Marshal(envelope)
		if err != nil {
			return e2eEnvelope{}, errors.New("inventory_envelope_invalid")
		}
		if len(body) <= inventoryEnvelopeMaxBytes {
			return envelope, nil
		}
		if !trimInventoryForSize(&doc) {
			return e2eEnvelope{}, errors.New("inventory_too_large")
		}
	}
}

// trimInventoryForSize gives up the least the App can live without, one step at
// a time, so a publish always fits: idle rows, then done, then working rows,
// then every message preview, and only then the rows the user opened the App
// for (oldest first).
func trimInventoryForSize(doc *inventory) bool {
	for _, state := range []string{"idle", "done", "working"} {
		if dropOldestRowInState(doc, state) {
			return true
		}
	}
	if emptyLongestMessage(doc) {
		return true
	}
	return dropOldestRow(doc)
}

// dropOldestRowInState removes the row of that state that has been quiet
// longest; an empty state is not a failure, the next step is tried.
func dropOldestRowInState(doc *inventory, state string) bool {
	return dropRow(doc, func(row inventoryConversation) bool { return row.State == state })
}

// dropOldestRow removes the oldest row, whatever its state. It is the last
// resort: a route the App can still open matters, a blob that never publishes
// does not exist.
func dropOldestRow(doc *inventory) bool {
	return dropRow(doc, func(inventoryConversation) bool { return true })
}

func dropRow(doc *inventory, keep func(inventoryConversation) bool) bool {
	oldest := -1
	for i, row := range doc.Conversations {
		if !keep(row) {
			continue
		}
		if oldest < 0 || row.Since < doc.Conversations[oldest].Since {
			oldest = i
		}
	}
	if oldest < 0 {
		return false
	}
	doc.Conversations = append(doc.Conversations[:oldest], doc.Conversations[oldest+1:]...)
	return true
}

// emptyLongestMessage drops the longest preview: the rows stay, tappable and
// readable by title, which is more than a dropped row would leave.
func emptyLongestMessage(doc *inventory) bool {
	longest, size := -1, 0
	for i, row := range doc.Conversations {
		if len(row.Message) > size {
			longest, size = i, len(row.Message)
		}
	}
	if longest < 0 {
		return false
	}
	doc.Conversations[longest].Message = ""
	return true
}

// ---------------------------------------------------------------------------
// Wire
// ---------------------------------------------------------------------------

// inventoryRelayURL is the lane's prefix on the relay, exactly what delivery
// uses, so a sandbox phone never reads the production lane's rows.
func inventoryRelayURL(base, lane string) string {
	switch lane {
	case "production", "testflight":
		return base + "/" + lane
	}
	return base
}

// inventorySender PUTs one sealed blob with the host credential. The body is the
// hostRef and the envelope and nothing else: the relay never sees plaintext.
func inventorySender(client *http.Client, base string) func(context.Context, inventoryTarget, e2eEnvelope) (int, error) {
	return func(ctx context.Context, target inventoryTarget, envelope e2eEnvelope) (int, error) {
		body, err := json.Marshal(map[string]any{"hostRef": target.HostRef, "envelope": envelope})
		if err != nil {
			return 0, errors.New("inventory_invalid")
		}
		req, err := http.NewRequestWithContext(ctx, "PUT", inventoryRelayURL(base, target.Lane)+"/v1/inventory", bytes.NewReader(body))
		if err != nil {
			return 0, errors.New("inventory_request_invalid")
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+target.Token)
		resp, err := client.Do(req)
		if err != nil {
			return 0, errors.New("network_unavailable")
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return resp.StatusCode, nil
	}
}

// ---------------------------------------------------------------------------
// Pairings
// ---------------------------------------------------------------------------

// inventoryTargets lists the private pairings in the credentials directory. A
// plaintext pairing is skipped by design, and one unreadable file never stops
// the others.
func inventoryTargets(dir string) ([]inventoryTarget, error) {
	if err := privatePath(dir, true); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	targets := []inventoryTarget{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		profile := strings.TrimSuffix(entry.Name(), ".json")
		c, code := loadCredential(dir, profile)
		if code != "" || c.E2E == nil {
			continue
		}
		phonePub, err := e2ePublicKey(c.E2E.Pub)
		if err != nil {
			continue
		}
		targets = append(targets, inventoryTarget{Profile: profile, Lane: c.Lane,
			HostRef: e2eHostRef(profile), Token: c.Token, PhonePub: phonePub})
		if len(targets) > maxInventoryTargets {
			break
		}
	}
	return targets, nil
}

// loadCredential reads one pairing file the way delivery does: private, schema
// 1, a valid host token, a valid phone key and a known lane. The code is the
// delivery error a failure means, empty on success.
func loadCredential(dir, profile string) (credential, string) {
	var c credential
	if !identifier.MatchString(profile) {
		return c, "invalid_credential"
	}
	if err := privatePath(dir, true); err != nil {
		return c, "credential_unavailable"
	}
	path := filepath.Join(dir, profile+".json")
	if err := privatePath(path, false); err != nil {
		return c, "credential_unavailable"
	}
	f, err := os.Open(path)
	if err != nil {
		return c, "credential_unavailable"
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 8193))
	if err != nil || len(raw) > 8192 {
		return c, "credential_unavailable"
	}
	if json.Unmarshal(raw, &c) != nil || c.Schema != 1 || !identifier.MatchString(c.Host) || len(c.Token) != 43 || !identifier.MatchString(c.Token) {
		return credential{}, "invalid_credential"
	}
	if c.E2E != nil && (c.E2E.V != 1 || !validE2EPublicKey(c.E2E.Pub)) {
		// A malformed key never falls back to plaintext: it stops delivery.
		return credential{}, "invalid_credential"
	}
	switch c.Lane {
	case "sandbox":
	case "production", "testflight":
	default:
		return credential{}, "invalid_credential"
	}
	return c, ""
}
