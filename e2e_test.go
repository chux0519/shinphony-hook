package main

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"golang.org/x/crypto/chacha20poly1305"
)

// e2eOpen is the phone's side in Go: the Swift check does the same with
// CryptoKit. It exists so the vectors and the trimming are verified end to end.
func e2eOpen(phonePriv *ecdh.PrivateKey, envelope e2eEnvelope, hostRef string) ([]byte, error) {
	ephRaw, err := base64.RawURLEncoding.Strict().DecodeString(envelope.EPK)
	if err != nil || envelope.V != e2eVersion {
		return nil, errInvalidE2E
	}
	eph, err := ecdh.X25519().NewPublicKey(ephRaw)
	if err != nil {
		return nil, err
	}
	phonePub := phonePriv.PublicKey().Bytes()
	shared, err := phonePriv.ECDH(eph)
	if err != nil {
		return nil, err
	}
	key, err := e2eDeriveKey(shared, ephRaw, phonePub)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(envelope.N)
	if err != nil || len(nonce) != e2eNonceBytes {
		return nil, errInvalidE2E
	}
	sealed, err := base64.RawURLEncoding.Strict().DecodeString(envelope.CT)
	if err != nil {
		return nil, errInvalidE2E
	}
	box, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return box.Open(nil, nonce, sealed, e2eAAD(hostRef))
}

var errInvalidE2E = &e2eError{"invalid_envelope"}

type e2eError struct{ code string }

func (e *e2eError) Error() string { return e.code }

func vectorBytes(label string, n int) []byte {
	sum := sha256.Sum256([]byte("shinphony-e2e-vectors-v1\x00" + label))
	return sum[:n]
}

func vectorKey(t *testing.T, label string) *ecdh.PrivateKey {
	t.Helper()
	key, err := ecdh.X25519().NewPrivateKey(vectorBytes(label, e2eKeyBytes))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func b64(value []byte) string { return base64.RawURLEncoding.EncodeToString(value) }

// e2eVectors is the cross-language fixture the Swift check reads.
type e2eVectors struct {
	Version             int         `json:"v"`
	Info                string      `json:"info"`
	HostRefDomain       string      `json:"hostRefDomain"`
	Profile             string      `json:"profile"`
	HostRef             string      `json:"hostRef"`
	AAD                 string      `json:"aad"`
	PhonePublicKey      string      `json:"phonePublicKey"`
	PhonePrivateKey     string      `json:"phonePrivateKey"`
	EphemeralPublicKey  string      `json:"ephemeralPublicKey"`
	EphemeralPrivateKey string      `json:"ephemeralPrivateKey"`
	Nonce               string      `json:"nonce"`
	Plaintext           string      `json:"plaintextJSON"`
	Envelope            e2eEnvelope `json:"envelope"`
	Notes               string      `json:"notes"`
}

const vectorProfile = "phone"
const vectorPlaintext = `{"category":"approval_required","agent":"claude","session":"0123456789abcdef0123456789abcdef","title":"Allow Bash?","body":"npm test -- --watch=false","project":"hook","visibility":"banner","lines":["$ npm test","61 passing","Done in 12.4s"]}`

func buildE2EVectors(t *testing.T) e2eVectors {
	t.Helper()
	phone, eph := vectorKey(t, "phone"), vectorKey(t, "ephemeral")
	nonce := vectorBytes("nonce", e2eNonceBytes)
	hostRef := e2eHostRef(vectorProfile)
	envelope, err := e2eSealWith(eph, nonce, phone.PublicKey().Bytes(), hostRef, []byte(vectorPlaintext))
	if err != nil {
		t.Fatal(err)
	}
	return e2eVectors{
		Version: e2eVersion, Info: e2eDomain, HostRefDomain: e2eHostRefDo,
		Profile: vectorProfile, HostRef: hostRef, AAD: string(e2eAAD(hostRef)),
		PhonePublicKey: b64(phone.PublicKey().Bytes()), PhonePrivateKey: b64(phone.Bytes()),
		EphemeralPublicKey: b64(eph.PublicKey().Bytes()), EphemeralPrivateKey: b64(eph.Bytes()),
		Nonce: b64(nonce), Plaintext: vectorPlaintext, Envelope: envelope,
		Notes: "Fixed test keys and nonce; derived from SHA-256 of their labels. Never use them for a real pairing.",
	}
}

// UPDATE_E2E_VECTORS=1 rewrites testdata/e2e_vectors.json; the committed file
// must match what this test regenerates.
func TestE2EVectors(t *testing.T) {
	path := filepath.Join("testdata", "e2e_vectors.json")
	want := buildE2EVectors(t)
	raw, err := json.MarshalIndent(want, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	if os.Getenv("UPDATE_E2E_VECTORS") == "1" {
		if err = os.WriteFile(path, raw, 0644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(raw) {
		t.Fatalf("%s is stale; rerun with UPDATE_E2E_VECTORS=1", path)
	}
	// The phone closes the vectors with its key and reads the vector plaintext.
	phone, err := ecdh.X25519().NewPrivateKey(vectorBytes("phone", e2eKeyBytes))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := e2eOpen(phone, want.Envelope, want.HostRef)
	if err != nil {
		t.Fatal(err)
	}
	if string(opened) != want.Plaintext {
		t.Fatal(string(opened))
	}
	if want.HostRef != e2eHostRef(want.Profile) || len(want.HostRef) != 22 {
		t.Fatal(want.HostRef)
	}
	// The deriving side is checkable from the document alone (the Swift test
	// does the same): SHA-256 of the domain and profile.
	sum := sha256.Sum256([]byte(want.HostRefDomain + want.Profile))
	if ifHostRef := b64(sum[:])[:22]; ifHostRef != want.HostRef {
		t.Fatal(ifHostRef, want.HostRef)
	}
}

func TestE2ESealRoundTripAndAD(t *testing.T) {
	phone := vectorKey(t, "phone")
	hostRef := e2eHostRef("phone")
	plaintext := []byte(`{"category":"task_complete","title":"done"}`)
	envelope, err := e2eSeal(randomReader, phone.PublicKey().Bytes(), hostRef, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := e2eOpen(phone, envelope, hostRef)
	if err != nil || string(opened) != string(plaintext) {
		t.Fatal(err, string(opened))
	}
	// hostRef is authenticated; another pairing's envelope never opens.
	if _, err = e2eOpen(phone, envelope, e2eHostRef("other")); err == nil {
		t.Fatal("wrong hostRef opened")
	}
	// Another phone key never opens it.
	if _, err = e2eOpen(vectorKey(t, "stranger"), envelope, hostRef); err == nil {
		t.Fatal("wrong key opened")
	}
	// Every seal uses a fresh ephemeral key and nonce.
	second, err := e2eSeal(randomReader, phone.PublicKey().Bytes(), hostRef, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if second.EPK == envelope.EPK || second.N == envelope.N || second.CT == envelope.CT {
		t.Fatal("envelope reused")
	}
}

func TestE2EHostRefIsOpaqueAndStable(t *testing.T) {
	ref := e2eHostRef("phone")
	if len(ref) != 22 || !identifier.MatchString(ref) {
		t.Fatal(ref)
	}
	if ref != e2eHostRef("phone") || ref == e2eHostRef("phone-2") {
		t.Fatal("hostRef is not per pairing")
	}
	// It is a hash, not the profile: the profile must not appear in it.
	if strings.Contains(ref, "phone") {
		t.Fatal(ref)
	}
}

func TestE2EFieldsWithinBounds(t *testing.T) {
	phone := vectorKey(t, "phone")
	hostRef := e2eHostRef("phone")
	// The deepest event the Hook can produce: 80 CJK characters of title, 200 of
	// body, a 64-character project and a bounded terminal preview. It must fit
	// without trimming, so the phone always sees the whole notification.
	details := &eventDetails{Category: "approval_required", Agent: "claude", Session: strings.Repeat("a", 32),
		Title: strings.Repeat("好", 80), Body: strings.Repeat("好", 200), Project: strings.Repeat("p", 64), Visibility: "banner"}
	context := &taskContext{Version: 1, Preview: strings.Repeat("一", 232) + "\n" + strings.Repeat("二", 232)}
	fields, err := e2eFields(randomReader, phone.PublicKey().Bytes(), hostRef, details, context)
	if err != nil {
		t.Fatal(err)
	}
	envelope, ok := fields["e2e"].(e2eEnvelope)
	if !ok {
		t.Fatal(fields)
	}
	raw, err := json.Marshal(envelope)
	if err != nil || len(raw) > e2eMaxEnvelope {
		t.Fatal(len(raw), err)
	}
	opened, err := e2eOpen(phone, envelope, hostRef)
	if err != nil {
		t.Fatal(err)
	}
	var p e2ePlaintext
	if err = json.Unmarshal(opened, &p); err != nil {
		t.Fatal(err)
	}
	if p.Title != details.Title || p.Body != details.Body || p.Project != details.Project ||
		p.Agent != details.Agent || p.Session != details.Session || p.Visibility != "banner" {
		t.Fatalf("%+v", p)
	}
	// The preview keeps whole lines up to its byte budget, never a partial rune.
	if len(p.Lines) == 0 || len(p.Lines) > e2eMaxLines || len(strings.Join(p.Lines, "\n")) > e2eMaxLineBytes ||
		!utf8.ValidString(strings.Join(p.Lines, "")) {
		t.Fatalf("lines: %q", p.Lines)
	}
	if fields["category"] != "approval_required" || fields["hostRef"] != hostRef || fields["silent"] != false {
		t.Fatal(fields)
	}
	for _, leaked := range []string{"title", "body", "project", "agent", "session", "visibility"} {
		if _, ok := fields[leaked]; ok {
			t.Fatalf("%s left in the request", leaked)
		}
	}
	// A silent event only says so; the text stays sealed.
	silent, err := e2eFields(randomReader, phone.PublicKey().Bytes(), hostRef,
		&eventDetails{Category: "task_started", Visibility: "silent"}, nil)
	if err != nil || silent["silent"] != true || silent["category"] != "task_started" {
		t.Fatal(silent, err)
	}
}

func TestE2ESealTrimsOversizedPlaintext(t *testing.T) {
	phone := vectorKey(t, "phone")
	hostRef := e2eHostRef("phone")
	// Not reachable from a real event (every field is bounded), but the relay
	// rejects a larger envelope, so the sender must trim rather than fail.
	p := &e2ePlaintext{Category: "task_complete", Agent: "claude", Session: strings.Repeat("a", 32),
		Title: strings.Repeat("好", 900), Body: strings.Repeat("b", 4000), Project: strings.Repeat("q", 300),
		Visibility: "banner", Lines: []string{strings.Repeat("line ", 400), strings.Repeat("more ", 400)}}
	title, body := len(p.Title), len(p.Body)
	envelope, err := e2eSealPlaintext(func(plaintext []byte) (e2eEnvelope, error) {
		return e2eSeal(randomReader, phone.PublicKey().Bytes(), hostRef, plaintext)
	}, p)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(envelope)
	if err != nil || len(raw) > e2eMaxEnvelope {
		t.Fatal(len(raw), err)
	}
	opened, err := e2eOpen(phone, envelope, hostRef)
	if err != nil {
		t.Fatal(err)
	}
	if !utf8.Valid(opened) {
		t.Fatal("trimming split a UTF-8 sequence")
	}
	var got e2ePlaintext
	if err = json.Unmarshal(opened, &got); err != nil {
		t.Fatal(err)
	}
	// Routing survives; the longest fields shrank on rune boundaries.
	if got.Category != "task_complete" || got.Agent != "claude" || got.Visibility != "banner" {
		t.Fatalf("%+v", got)
	}
	if len(got.Title) >= title || len(got.Body) >= body {
		t.Fatalf("not trimmed: %d %d", len(got.Title), len(got.Body))
	}
	if !strings.HasPrefix(p.Title, got.Title) || !utf8.ValidString(got.Title) {
		t.Fatalf("title not a clean prefix: %q", got.Title)
	}
	if len(got.Lines) > e2eMaxLines {
		t.Fatalf("lines: %d", len(got.Lines))
	}
}

func TestE2EFieldsNeedCategory(t *testing.T) {
	phone := vectorKey(t, "phone")
	if _, err := e2eFields(randomReader, phone.PublicKey().Bytes(), e2eHostRef("phone"), &eventDetails{Title: "x"}, nil); err == nil {
		t.Fatal("sealed details without a category")
	}
}

func TestE2EPublicKeyValidation(t *testing.T) {
	phone := vectorKey(t, "phone")
	if !validE2EPublicKey(b64(phone.PublicKey().Bytes())) {
		t.Fatal("valid key rejected")
	}
	longer := b64(vectorBytes("k", 32)) + "AA"
	for _, bad := range []string{"", "short", b64(vectorBytes("k", 31)), longer,
		strings.ReplaceAll(b64(vectorBytes("k", 32)), "A", "+"), b64(vectorBytes("k", 32)) + "="} {
		if validE2EPublicKey(bad) {
			t.Fatalf("accepted %q", bad)
		}
	}
}
