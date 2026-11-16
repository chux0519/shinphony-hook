package main

// Inventory publishing (design: ShinphonyApp docs/design/agent_first_layout_
// 20261115.md §1, §4). The daemon seals its inventory to every private pairing
// and PUTs it to the relay; the phone reads it without an SSH connection.
import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// inventorySent is one accepted publish, as the fake relay saw it.
type inventorySent struct {
	target   inventoryTarget
	envelope e2eEnvelope
	at       time.Time
}

// publishFixture is a publisher over a fake relay: the clock is the test's, the
// inventory is whatever the test builds, and every publish and build is
// counted.
type publishFixture struct {
	p      *inventoryPublisher
	now    time.Time
	sent   []inventorySent
	builds int
	fail   int
	status int
	inv    inventory
	target []inventoryTarget
	err    error
}

func newPublishFixture(t *testing.T, phone *ecdh.PrivateKey, targets ...inventoryTarget) *publishFixture {
	t.Helper()
	f := &publishFixture{now: time.Unix(1800000000, 0), status: 200, target: targets}
	if len(targets) == 0 {
		f.target = []inventoryTarget{{Profile: "phone", Lane: "sandbox", HostRef: e2eHostRef("phone"),
			Token: strings.Repeat("a", 43), PhonePub: phone.PublicKey().Bytes()}}
	}
	f.inv = inventory{Schema: inventorySchema, GeneratedAt: f.now.Unix(), Host: "studio",
		Conversations: []inventoryConversation{}, Errors: []string{}}
	f.p = &inventoryPublisher{
		Now: func() time.Time { return f.now },
		Build: func(context.Context) inventory {
			f.builds++
			return f.inv
		},
		Targets: func() ([]inventoryTarget, error) { return f.target, f.err },
		Seal:    e2eSeal,
		Send: func(ctx context.Context, target inventoryTarget, envelope e2eEnvelope) (int, error) {
			f.sent = append(f.sent, inventorySent{target: target, envelope: envelope, at: f.now})
			if f.fail > 0 {
				f.fail--
				return 429, nil
			}
			return f.status, nil
		},
		states: map[string]*inventoryPublishState{},
	}
	return f
}

// tick advances the fake clock and runs one scheduler pass.
func (f *publishFixture) tick(after time.Duration) {
	f.now = f.now.Add(after)
	f.p.step(context.Background(), f.now)
}

// quiet runs one scheduler pass per second, as the real loop does.
func (f *publishFixture) quiet(seconds int) {
	for i := 0; i < seconds; i++ {
		f.tick(time.Second)
	}
}

// event is an agent event (or a pairing change) arriving now: it only arms the
// debounced rebuild, exactly like the non-blocking signal in the daemon.
func (f *publishFixture) event() { f.p.scheduleRebuild(f.now) }

func (f *publishFixture) published() []time.Time {
	out := make([]time.Time, 0, len(f.sent))
	for _, s := range f.sent {
		out = append(out, s.at)
	}
	return out
}

func inventoryRows(n int, state string) []inventoryConversation {
	rows := make([]inventoryConversation, 0, n)
	for i := 0; i < n; i++ {
		rows = append(rows, inventoryConversation{
			ID: fmt.Sprintf("c_%016d", i), Mux: "tmux",
			Group: inventoryGroup{Kind: "tmuxSession", Name: "work"}, Title: strings.Repeat("t", 120),
			Directory: "/Users/someone/src/project-name", Agent: ptr("claude"), State: state, StateSource: "hook",
			Since: int64(1000 + i), Message: strings.Repeat("m", 120),
			Route: inventoryRoute{Version: 1, Agent: "claude", Title: strings.Repeat("t", 120),
				Multiplexer: "tmux", Session: "work", Window: strings.Repeat("w", 80), Route: "route"},
		})
	}
	return rows
}

func ptr(value string) *string { return &value }

// A private pairing receives one sealed blob; a lane without the phone key is
// never published to, so nothing readable can leave the machine. The pairings
// are read from a real directory, so the filter is the one the daemon uses.
func TestInventoryPublishSealsToPrivatePairingsOnly(t *testing.T) {
	phone := vectorKey(t, "phone")
	creds := filepath.Join(privateTemp(t), "credentials")
	if err := prepareDir(creds); err != nil {
		t.Fatal(err)
	}
	for profile, value := range map[string]map[string]any{
		"phone": {"schema": 1, "lane": "sandbox", "hostId": "host", "hostToken": strings.Repeat("a", 43),
			"e2e": map[string]any{"v": 1, "pub": b64(phone.PublicKey().Bytes())}},
		"legacy": {"schema": 1, "lane": "sandbox", "hostId": "host", "hostToken": strings.Repeat("b", 43)},
	} {
		raw, _ := json.Marshal(value)
		if err := os.WriteFile(filepath.Join(creds, profile+".json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	f := newPublishFixture(t, phone)
	f.p.Targets = func() ([]inventoryTarget, error) { return inventoryTargets(creds) }
	f.inv.Conversations = inventoryRows(2, "working")
	f.tick(0)
	if len(f.sent) != 1 {
		t.Fatalf("published %d times, want 1 (plaintext lane must not publish)", len(f.sent))
	}
	sent := f.sent[0]
	if sent.target.Profile != "phone" || sent.target.HostRef != e2eHostRef("phone") {
		t.Fatal(sent.target)
	}
	raw, err := e2eOpen(phone, sent.envelope, sent.target.HostRef)
	if err != nil {
		t.Fatal(err)
	}
	var got inventory
	if err = json.Unmarshal(raw, &got); err != nil || got.Schema != inventorySchema || len(got.Conversations) != 2 {
		t.Fatalf("%v %+v", err, got)
	}
	// The blob is sealed: the readable request never names a conversation.
	body, _ := json.Marshal(map[string]any{"hostRef": sent.target.HostRef, "envelope": sent.envelope})
	for _, leak := range []string{"work", "claude", "project-name", "conversations"} {
		if strings.Contains(string(body), leak) {
			t.Fatalf("plaintext %q left the machine: %s", leak, body)
		}
	}
}

// Quiet costs nothing: after the first publish the daemon lists nothing until
// the slow mux poll. An agent event (even a session start that never notifies)
// rebuilds once, three seconds later, and a burst is one rebuild.
func TestInventoryPublishRebuildsOnAgentEvents(t *testing.T) {
	f := newPublishFixture(t, vectorKey(t, "phone"))
	f.tick(0) // first sight: publish at once, so the phone has data
	if got := f.published(); len(got) != 1 || got[0].Sub(time.Unix(1800000000, 0)) != 0 {
		t.Fatalf("first publish: %v", got)
	}
	f.quiet(9)
	if f.builds != 1 {
		t.Fatalf("listed %d times while quiet, want 1", f.builds)
	}
	// One event: the rebuild lands on the debounce, not before it.
	f.event() // arrives at t+9
	f.tick(time.Second)
	f.tick(time.Second) // t+11
	if f.builds != 1 {
		t.Fatalf("rebuilt before the debounce: %d builds", f.builds)
	}
	f.tick(time.Second) // t+12: 3s after the event
	if f.builds != 2 {
		t.Fatalf("event did not rebuild: %d builds", f.builds)
	}
	// Unchanged content is not republished.
	if len(f.sent) != 1 {
		t.Fatalf("identical content republished: %v", f.published())
	}
	// A burst moves the rebuild to its last event, and the change is published.
	f.inv.Conversations = inventoryRows(2, "working")
	f.event()               // t+12
	f.tick(time.Second)     // t+13
	f.event()               // moves the rebuild to t+16
	f.tick(3 * time.Second) // t+16: one rebuild for the burst
	if f.builds != 3 {
		t.Fatalf("burst was not coalesced: %d builds", f.builds)
	}
	if len(f.sent) != 2 {
		t.Fatalf("coalesced change not published: %v", f.published())
	}
}

// Mux-only changes (a new tmux window, a renamed terminal) have no event: the
// slow poll picks them up, and only while a private pairing exists.
func TestInventoryPublishSlowPollOnlyWithAPrivatePairing(t *testing.T) {
	f := newPublishFixture(t, vectorKey(t, "phone"))
	f.tick(0)
	f.quiet(29)
	if f.builds != 1 {
		t.Fatalf("polled %d times in 29 s of quiet, want no poll", f.builds)
	}
	f.tick(time.Second) // t+30
	if f.builds != 2 {
		t.Fatalf("slow poll missing: %d builds", f.builds)
	}
	if len(f.sent) != 1 {
		t.Fatalf("unchanged content republished by the poll: %v", f.published())
	}
	// A mux-only change is published at the next poll, with no event at all.
	f.inv.Conversations = inventoryRows(1, "working")
	f.quiet(30) // t+60
	if len(f.sent) != 2 {
		t.Fatalf("mux-only change not published by the poll: %v", f.published())
	}
	// No private pairing: not one listing, ever.
	f.target = []inventoryTarget{}
	f.quiet(120)
	if f.builds != 3 {
		t.Fatalf("listed %d times without a private pairing", f.builds-3)
	}
}

// The ten-second floor holds even when a rebuild lands earlier.
func TestInventoryPublishKeepsTheFloorForEventRebuilds(t *testing.T) {
	f := newPublishFixture(t, vectorKey(t, "phone"))
	f.tick(0) // publish at t0
	f.tick(5 * time.Second)
	f.inv.Conversations = inventoryRows(1, "working")
	f.event() // rebuild due t+8
	f.tick(3 * time.Second)
	if f.builds != 2 || len(f.sent) != 1 {
		t.Fatalf("build %d, publish %v: want a rebuild but no publish inside the floor", f.builds, f.published())
	}
	f.quiet(1) // t+9
	if len(f.sent) != 1 {
		t.Fatalf("published inside the rate window: %v", f.published())
	}
	f.tick(time.Second) // t+10
	if len(f.sent) != 2 {
		t.Fatalf("floor did not release the publish: %v", f.published())
	}
}

// A heartbeat republishes unchanged content every ten minutes, so the App's
// freshness is visible even on a quiet host. It rebuilds too: a blob whose
// generatedAt is hours old is not "fresh", whatever the relay says.
func TestInventoryPublishHeartbeatsWhileIdle(t *testing.T) {
	f := newPublishFixture(t, vectorKey(t, "phone"))
	f.tick(0)
	f.quiet(599)
	if len(f.sent) != 1 {
		t.Fatalf("published before the heartbeat: %v", f.published())
	}
	builds := f.builds
	f.tick(time.Second) // t+600
	if len(f.sent) != 2 {
		t.Fatalf("heartbeat missing: %v", f.published())
	}
	if f.builds == builds {
		t.Fatal("the heartbeat reused a stale document")
	}
	f.quiet(600)
	if len(f.sent) != 3 {
		t.Fatalf("second heartbeat missing: %v", f.published())
	}
}

// The generator moves on every build; the row set and the states do not, so
// timestamp-only churn is not a change.
func TestInventoryPublishIgnoresTimestampChurn(t *testing.T) {
	f := newPublishFixture(t, vectorKey(t, "phone"))
	f.inv.Conversations = inventoryRows(2, "working")
	f.tick(0)
	before := inventoryFingerprint(f.inv)
	f.inv.GeneratedAt += 42
	for i := range f.inv.Conversations {
		f.inv.Conversations[i].Since += 5
	}
	if after := inventoryFingerprint(f.inv); after != before {
		t.Fatal("generatedAt/since counted as a change")
	}
	f.event()
	f.tick(3 * time.Second)
	if len(f.sent) != 1 {
		t.Fatalf("republished on timestamp churn: %v", f.published())
	}
	// A real change (a title) is still a change, once the floor has passed.
	f.quiet(7) // t+10
	f.inv.Conversations[0].Title = "renamed"
	f.event()
	f.tick(3 * time.Second) // t+13
	if len(f.sent) != 2 {
		t.Fatalf("title change not published: %v", f.published())
	}
}

// The blob that reaches the relay is at most 24 KB: the oldest idle rows go
// first, and a working row is never dropped to make room.
func TestInventoryPublishDropsOldestIdleRowsToFit(t *testing.T) {
	f := newPublishFixture(t, vectorKey(t, "phone"))
	idle := inventoryRows(100, "idle")   // oldest
	busy := inventoryRows(20, "working") // newer, must all survive
	for i := range busy {
		busy[i].ID = fmt.Sprintf("b_%016d", i)
		busy[i].Since = int64(5000 + i)
	}
	f.inv.Conversations = append(append([]inventoryConversation{}, idle...), busy...)
	if raw, _ := json.Marshal(f.inv); len(raw) < inventoryEnvelopeMaxBytes {
		t.Fatalf("fixture too small to exercise the cap: %d", len(raw))
	}
	f.tick(0)
	if len(f.sent) != 1 {
		t.Fatalf("published %d times: %v", len(f.sent), f.published())
	}
	body, _ := json.Marshal(f.sent[0].envelope)
	if len(body) > inventoryEnvelopeMaxBytes {
		t.Fatalf("envelope %d bytes > %d", len(body), inventoryEnvelopeMaxBytes)
	}
	raw, err := e2eOpen(vectorKey(t, "phone"), f.sent[0].envelope, f.sent[0].target.HostRef)
	if err != nil {
		t.Fatal(err)
	}
	var got inventory
	if err = json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Conversations) >= len(f.inv.Conversations) || len(got.Conversations) == 0 {
		t.Fatalf("nothing was trimmed: %d", len(got.Conversations))
	}
	kept := map[string]bool{}
	for _, row := range got.Conversations {
		kept[row.ID] = true
	}
	for _, row := range busy {
		if !kept[row.ID] {
			t.Fatalf("working row %s dropped", row.ID)
		}
	}
	// Dropped idle rows are the oldest ones: nothing kept is older than them.
	oldestKept := int64(1 << 62)
	dropped := 0
	for _, row := range idle {
		if kept[row.ID] {
			if row.Since < oldestKept {
				oldestKept = row.Since
			}
			continue
		}
		dropped++
		if row.Since > oldestKept {
			t.Fatalf("row %d kept while older row %d dropped", row.Since, oldestKept)
		}
	}
	if dropped == 0 {
		t.Fatal("expected idle rows to be dropped")
	}
}

// Unpairing stops publishing at once; re-pairing publishes the same inventory
// again instead of trusting a hash from the pairing that is gone.
func TestInventoryPublishStopsOnUnpairAndResumesOnRepair(t *testing.T) {
	f := newPublishFixture(t, vectorKey(t, "phone"))
	f.tick(0)
	paired := f.target
	f.target = []inventoryTarget{}
	f.tick(time.Second)
	if len(f.sent) != 1 {
		t.Fatalf("published after unpair: %v", f.published())
	}
	if len(f.p.states) != 0 {
		t.Fatal("publisher kept state for an unpaired profile")
	}
	f.target = paired
	f.tick(time.Second)
	if len(f.sent) != 2 {
		t.Fatalf("re-pair did not publish immediately: %v", f.published())
	}
	// Reading the pairing directory can fail while it is being written; that is
	// not a reason to publish to a guess, and it is not fatal either.
	f.err = os.ErrPermission
	f.inv.Conversations = inventoryRows(1, "working")
	f.tick(20 * time.Second)
	if len(f.sent) != 2 {
		t.Fatalf("published while the pairings were unreadable: %v", f.published())
	}
	f.err = nil
	f.event()
	f.tick(3 * time.Second)
	if len(f.sent) != 3 {
		t.Fatalf("did not recover after the pairings were readable: %v", f.published())
	}
}

// A refused publish backs off and retries; it never spins or gives up.
func TestInventoryPublishBacksOffAfterFailure(t *testing.T) {
	f := newPublishFixture(t, vectorKey(t, "phone"))
	f.fail = 1
	f.tick(0)
	if len(f.sent) != 1 {
		t.Fatalf("first attempt missing: %v", f.published())
	}
	for i := 0; i < 9; i++ {
		f.tick(time.Second)
	}
	if len(f.sent) != 1 {
		t.Fatalf("retried before the backoff: %v", f.published())
	}
	f.tick(time.Second) // 10s after the failure
	if len(f.sent) != 2 {
		t.Fatalf("backoff retry missing: %v", f.published())
	}
	// The retry succeeded, so the next change publishes without a backoff — as
	// soon as the ten-second floor that started at the retry allows it.
	f.inv.Conversations = inventoryRows(1, "working")
	f.event()               // t0+10
	f.tick(3 * time.Second) // t0+13: rebuilt, but the floor still holds
	if len(f.sent) != 2 {
		t.Fatalf("published inside the floor: %v", f.published())
	}
	f.quiet(7) // t0+20: 10s after the retry
	if len(f.sent) != 3 {
		t.Fatalf("publish after recovery missing: %v", f.published())
	}
}

// The wire request names the pairing the relay knows (hostRef) and the lane's
// prefix, and carries nothing but the envelope.
func TestInventorySenderUsesLanePrefixAndOpaqueBody(t *testing.T) {
	var got struct {
		method, path, auth string
		body               map[string]any
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.method, got.path, got.auth = r.Method, r.URL.Path, r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		json.Unmarshal(raw, &got.body)
		w.Write([]byte(`{"accepted":true}`))
	}))
	defer srv.Close()
	phone := vectorKey(t, "phone")
	envelope, err := e2eSeal(randomReader, phone.PublicKey().Bytes(), e2eHostRef("phone"), []byte(`{"schema":1}`))
	if err != nil {
		t.Fatal(err)
	}
	send := inventorySender(srv.Client(), srv.URL)
	status, err := send(context.Background(), inventoryTarget{Profile: "phone", Lane: "sandbox",
		HostRef: e2eHostRef("phone"), Token: strings.Repeat("a", 43)}, envelope)
	if err != nil || status != 200 {
		t.Fatal(status, err)
	}
	if got.method != "PUT" || got.path != "/v1/inventory" || got.auth != "Bearer "+strings.Repeat("a", 43) {
		t.Fatal(got.method, got.path, got.auth)
	}
	if got.body["hostRef"] != e2eHostRef("phone") || got.body["envelope"] == nil {
		t.Fatal(got.body)
	}
	if len(got.body) != 2 {
		t.Fatalf("request carries more than the envelope: %v", got.body)
	}
	// A production pairing is published under the lane prefix the relay uses.
	status, err = send(context.Background(), inventoryTarget{Profile: "phone", Lane: "production",
		HostRef: e2eHostRef("phone"), Token: strings.Repeat("a", 43)}, envelope)
	if err != nil || status != 200 || got.path != "/production/v1/inventory" {
		t.Fatal(status, err, got.path)
	}
	// A refused publish is a status, not a panic, and the body is bounded.
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(429)
		w.Write([]byte(`{"error":"rate_limit"}`))
	}))
	defer failing.Close()
	if status, err = inventorySender(failing.Client(), failing.URL)(context.Background(),
		inventoryTarget{Profile: "phone", Lane: "sandbox", HostRef: e2eHostRef("phone"), Token: strings.Repeat("a", 43)}, envelope); err != nil || status != 429 {
		t.Fatal(status, err)
	}
}

// The pairing directory decides who receives a blob: only a private pairing
// has the key the seal needs, and a broken file never stops the others.
func TestInventoryTargetsReadPrivatePairingsOnly(t *testing.T) {
	creds := filepath.Join(privateTemp(t), "credentials")
	if err := prepareDir(creds); err != nil {
		t.Fatal(err)
	}
	phone := vectorKey(t, "phone")
	private := map[string]any{"schema": 1, "lane": "production", "hostId": "host", "hostToken": strings.Repeat("a", 43),
		"e2e": map[string]any{"v": 1, "pub": b64(phone.PublicKey().Bytes())}}
	plain := map[string]any{"schema": 1, "lane": "sandbox", "hostId": "host", "hostToken": strings.Repeat("b", 43)}
	for name, value := range map[string]any{"phone": private, "legacy": plain, "broken": "not a credential"} {
		raw, _ := json.Marshal(value)
		if err := os.WriteFile(filepath.Join(creds, name+".json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	targets, err := inventoryTargets(creds)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0].Profile != "phone" {
		t.Fatalf("%+v", targets)
	}
	if targets[0].HostRef != e2eHostRef("phone") || targets[0].Lane != "production" ||
		targets[0].Token != strings.Repeat("a", 43) || len(targets[0].PhonePub) != e2eKeyBytes {
		t.Fatalf("%+v", targets[0])
	}
	// An unreadable directory publishes nothing and is not an error to crash on.
	if _, err = inventoryTargets(filepath.Join(privateTemp(t), "missing")); err == nil {
		t.Fatal("missing pairing directory read successfully")
	}
}

// The publish job is not on the notification path: a relay that never answers
// must not delay a notification by even one event.
func TestInventoryPublishNeverDelaysNotificationDelivery(t *testing.T) {
	home := privateTemp(t)
	t.Setenv("HOME", home)
	dir := filepath.Join(home, "state")
	creds := filepath.Join(home, "credentials")
	for _, p := range []string{dir, creds} {
		if err := prepareDir(p); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(creds, "phone.json"), e2eCredentialBody(t, false), 0600); err != nil {
		t.Fatal(err)
	}
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(started) })
		<-release
		w.Write([]byte(`{"accepted":true}`))
	}))
	t.Cleanup(srv.Close) // registered first, so it runs last: release must come first
	previous := inventoryRelayBase
	inventoryRelayBase = srv.URL
	t.Cleanup(func() { inventoryRelayBase = previous; close(release) })

	ctx, cancel := context.WithCancel(context.Background())
	delivered := make(chan Event, 4)
	done := make(chan error, 1)
	go func() {
		done <- serve(ctx, dir, func(c context.Context, e Event) result {
			delivered <- e
			return result{Code: "accepted"}
		}, creds)
	}()
	t.Cleanup(func() { cancel(); <-done })

	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("the publisher never reached the relay")
	}
	// The publish request is still open: a notification must still be delivered.
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dialLocal(ctx, dir) }}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	resp, err := client.Post("http://local/v1/events", "application/json",
		strings.NewReader(`{"profile":"phone","eventId":"event1","status":"completed"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	select {
	case e := <-delivered:
		if e.ID != "event1" {
			t.Fatalf("delivered %+v", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a blocked inventory publish held up notification delivery")
	}
}

// The daemon wires an agent event into the publisher: a hook call rebuilds the
// inventory within the debounce, long before the 30 s mux poll could.
func TestInventoryPublishRebuildsOnADaemonAgentEvent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake multiplexer is a shell script")
	}
	home := privateTemp(t)
	t.Setenv("HOME", home)
	// The hc side of the build must not find a real core on this machine.
	t.Setenv("HC_SOCKET", "")
	t.Setenv("XDG_STATE_HOME", "")
	dir := filepath.Join(home, "state")
	creds := filepath.Join(home, "credentials")
	for _, path := range []string{dir, creds} {
		if err := prepareDir(path); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(creds, "phone.json"), e2eCredentialBody(t, false), 0600); err != nil {
		t.Fatal(err)
	}
	// A fake tmux with one window whose name can change while the daemon runs:
	// a mux-only change no event reports, so only the poll or the event wake can
	// pick it up.
	bin := filepath.Join(home, "bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	windows := filepath.Join(home, "windows")
	rename := func(name string) {
		line := "work\t$1\t0\t" + name + "\t@1\t" + strconv.FormatInt(time.Now().Unix(), 10) +
			"\t%1\t/tmp/proj\tnode\t/tmp/tmux.sock\n"
		if err := os.WriteFile(windows, []byte(line), 0600); err != nil {
			t.Fatal(err)
		}
	}
	rename("one")
	if err := os.WriteFile(filepath.Join(bin, "tmux"), []byte("#!/bin/sh\ncat "+windows+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	published := make(chan e2eEnvelope, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			HostRef  string      `json:"hostRef"`
			Envelope e2eEnvelope `json:"envelope"`
		}
		if json.NewDecoder(r.Body).Decode(&body) == nil {
			select {
			case published <- body.Envelope:
			default:
			}
		}
		w.Write([]byte(`{"accepted":true}`))
	}))
	t.Cleanup(srv.Close)
	previous := inventoryRelayBase
	inventoryRelayBase = srv.URL
	t.Cleanup(func() { inventoryRelayBase = previous })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- serve(ctx, dir, func(context.Context, Event) result { return result{Code: "accepted"} }, creds)
	}()
	t.Cleanup(func() { cancel(); <-done })

	phone := vectorKey(t, "phone")
	doc := func(envelope e2eEnvelope) inventory {
		t.Helper()
		raw, err := e2eOpen(phone, envelope, e2eHostRef("phone"))
		if err != nil {
			t.Fatal(err)
		}
		var inv inventory
		if err = json.Unmarshal(raw, &inv); err != nil {
			t.Fatal(err)
		}
		return inv
	}
	next := func(within time.Duration) inventory {
		t.Helper()
		select {
		case envelope := <-published:
			return doc(envelope)
		case <-time.After(within):
			t.Fatal("no inventory blob arrived")
			return inventory{}
		}
	}
	first := next(10 * time.Second)
	if len(first.Conversations) != 1 || first.Conversations[0].Title != "one" {
		t.Fatalf("first blob: %+v", first.Conversations)
	}

	rename("two")
	// A hook call is the only signal: it never notifies, it only wakes the
	// publisher, which rebuilds three seconds later.
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dialLocal(ctx, dir) }}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	resp, err := client.Post("http://local/v1/agent-events", "application/json",
		strings.NewReader(`{"agent":"claude","kind":"session_start","session":"session-1"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	// The first publish started the ten-second floor, so the change waits for
	// it — still long before the 30 s poll, which is what the wake replaces.
	second := next(15 * time.Second)
	if len(second.Conversations) != 1 || second.Conversations[0].Title != "two" {
		t.Fatalf("event did not rebuild the inventory: %+v", second.Conversations)
	}
}

// The fingerprint must be stable across processes: same document, same bytes.
func TestInventoryFingerprintIsContentAddressed(t *testing.T) {
	inv := inventory{Schema: inventorySchema, GeneratedAt: 5, Host: "h",
		Conversations: inventoryRows(2, "working"), Errors: []string{}}
	other := inv
	other.GeneratedAt = 99
	other.Conversations = append([]inventoryConversation{}, inv.Conversations...)
	for i := range other.Conversations {
		other.Conversations[i].Since += 100
	}
	if inventoryFingerprint(inv) != inventoryFingerprint(other) {
		t.Fatal("timestamps changed the fingerprint")
	}
	if len(inventoryFingerprint(inv)) != 64 {
		t.Fatal("fingerprint is not a sha256 hex digest")
	}
	changed := inv
	changed.Conversations = append([]inventoryConversation(nil), inv.Conversations...)
	changed.Conversations[0].State = "question"
	if inventoryFingerprint(inv) == inventoryFingerprint(changed) {
		t.Fatal("state change kept the fingerprint")
	}
}

// A document just under the bound is published unchanged.
func TestSealInventoryLeavesAFittingDocumentAlone(t *testing.T) {
	phone := vectorKey(t, "phone")
	seal := func(raw []byte) (e2eEnvelope, error) {
		return e2eSeal(randomReader, phone.PublicKey().Bytes(), e2eHostRef("phone"), raw)
	}
	small := inventory{Schema: inventorySchema, Host: "h", Conversations: inventoryRows(1, "working"), Errors: []string{}}
	envelope, err := sealInventory(seal, small)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(envelope)
	if len(body) > inventoryEnvelopeMaxBytes {
		t.Fatal(len(body))
	}
	if _, err = base64.RawURLEncoding.Strict().DecodeString(envelope.CT); err != nil {
		t.Fatal(err)
	}
}

// 200 rows of long titles are more than the relay takes. Every trim step is
// tried, so the publish fits instead of the host failing forever.
func TestInventoryPublishAlwaysFitsTheBound(t *testing.T) {
	phone := vectorKey(t, "phone")
	f := newPublishFixture(t, phone)
	f.inv.Conversations = inventoryRows(200, "working")
	f.tick(0)
	if len(f.sent) != 1 {
		t.Fatalf("a large inventory must still publish: %v", f.published())
	}
	body, _ := json.Marshal(f.sent[0].envelope)
	if len(body) > inventoryEnvelopeMaxBytes {
		t.Fatalf("envelope %d bytes > %d", len(body), inventoryEnvelopeMaxBytes)
	}
	raw, err := e2eOpen(phone, f.sent[0].envelope, f.sent[0].target.HostRef)
	if err != nil {
		t.Fatal(err)
	}
	var got inventory
	if err = json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Conversations) == 0 || len(got.Conversations) >= 200 {
		t.Fatalf("published %d rows", len(got.Conversations))
	}
	// Rows keep their identity: the App can still open what is left.
	for _, row := range got.Conversations {
		if row.ID == "" || row.Route.Route == "" {
			t.Fatalf("a kept row lost its route: %+v", row)
		}
	}
}

// When only rows the user needs are left, the text goes before the rows: an
// approval with an empty preview is still tappable.
func TestSealInventoryEmptiesMessagesBeforeDroppingNeededRows(t *testing.T) {
	phone := vectorKey(t, "phone")
	seal := func(raw []byte) (e2eEnvelope, error) {
		return e2eSeal(randomReader, phone.PublicKey().Bytes(), e2eHostRef("phone"), raw)
	}
	rows := inventoryRows(25, "approval")
	if raw, _ := json.Marshal(inventory{Schema: inventorySchema, Conversations: rows, Errors: []string{}}); len(raw)*4/3 <= inventoryEnvelopeMaxBytes {
		t.Fatalf("fixture does not exercise the bound: %d bytes", len(raw))
	}
	inv := inventory{Schema: inventorySchema, Host: "h", Conversations: rows, Errors: []string{}}
	envelope, err := sealInventory(seal, inv)
	if err != nil {
		t.Fatalf("a document that fits once the previews are gone was refused: %v", err)
	}
	body, _ := json.Marshal(envelope)
	if len(body) > inventoryEnvelopeMaxBytes {
		t.Fatalf("envelope %d bytes > %d", len(body), inventoryEnvelopeMaxBytes)
	}
	raw, err := e2eOpen(phone, envelope, e2eHostRef("phone"))
	if err != nil {
		t.Fatal(err)
	}
	var got inventory
	if err = json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Conversations) != len(rows) {
		t.Fatalf("dropped %d approval rows before emptying their previews", len(rows)-len(got.Conversations))
	}
	emptied := 0
	for _, row := range got.Conversations {
		if row.Message == "" {
			emptied++
		}
	}
	if emptied == 0 {
		t.Fatal("fitted without giving up a single preview")
	}
	// The caller's document is not mutated by the trim: the next pairing gets
	// the full inventory.
	if inv.Conversations[0].Message == "" {
		t.Fatal("sealing mutated the document it was given")
	}
}

// The last resort: drop rows (oldest first), never lose the publish.
func TestSealInventoryDropsRowsAsTheLastResort(t *testing.T) {
	phone := vectorKey(t, "phone")
	seal := func(raw []byte) (e2eEnvelope, error) {
		return e2eSeal(randomReader, phone.PublicKey().Bytes(), e2eHostRef("phone"), raw)
	}
	rows := inventoryRows(200, "approval")
	inv := inventory{Schema: inventorySchema, Host: "h", Conversations: rows, Errors: []string{}}
	envelope, err := sealInventory(seal, inv)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := e2eOpen(phone, envelope, e2eHostRef("phone"))
	if err != nil {
		t.Fatal(err)
	}
	var got inventory
	if err = json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Conversations) == 0 || len(got.Conversations) >= len(rows) {
		t.Fatalf("published %d of %d rows", len(got.Conversations), len(rows))
	}
	kept := map[string]bool{}
	for _, row := range got.Conversations {
		kept[row.ID] = true
	}
	// The newest rows survive; the oldest go first.
	maxDropped := int64(-1)
	minKept := int64(1 << 62)
	for _, row := range rows {
		if kept[row.ID] {
			if row.Since < minKept {
				minKept = row.Since
			}
			continue
		}
		if row.Since > maxDropped {
			maxDropped = row.Since
		}
	}
	if maxDropped > minKept {
		t.Fatalf("kept row %d while dropping older row %d", minKept, maxDropped)
	}
}
