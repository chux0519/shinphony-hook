//go:build darwin || linux

package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

type sshPairVector struct {
	Invitation sshPairInvitation `json:"invitation"`
	Hello      sshPairMessage    `json:"hello"`
	Key        sshPairMessage    `json:"key"`
	Receipt    sshPairMessage    `json:"receipt"`
	HostAuth   string            `json:"hostAuth"`
	PhoneAuth  string            `json:"phoneAuth"`
	SAS        string            `json:"sas"`
}

func pairVector(t *testing.T) sshPairVector {
	t.Helper()
	raw, err := os.ReadFile("testdata/ssh-pair-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector sshPairVector
	if json.Unmarshal(raw, &vector) != nil {
		t.Fatal("invalid test vector")
	}
	return vector
}
func TestSSHPairCrossLanguageVectorAndTampering(t *testing.T) {
	v := pairVector(t)
	inv := v.Invitation
	if inv.auth("host") != v.HostAuth || inv.auth("phone") != v.PhoneAuth || inv.sas(v.Hello, v.Key) != v.SAS {
		t.Fatal("cross-language MAC differs")
	}
	if _, err := inv.verifyKey(v.Key, v.Hello, "testuser"); err != nil {
		t.Fatal(err)
	}
	if _, err := inv.open(v.Receipt, "receipt"); err != nil {
		t.Fatal(err)
	}
	damaged := v.Key
	damaged.Payload = damaged.Payload[:len(damaged.Payload)-1] + "A"
	if _, err := inv.verifyKey(damaged, v.Hello, "testuser"); err == nil {
		t.Fatal("tampered payload accepted")
	}
	damaged = v.Key
	damaged.Proof = base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	if _, err := inv.verifyKey(damaged, v.Hello, "testuser"); err == nil {
		t.Fatal("invalid proof accepted")
	}
	if _, err := inv.verifyKey(v.Key, v.Hello, "another-user"); err == nil {
		t.Fatal("cross-user replay accepted")
	}
	wrong := inv
	wrong.ID = base64.RawURLEncoding.EncodeToString(make([]byte, 16))
	if _, err := wrong.verifyKey(v.Key, v.Hello, "testuser"); err == nil {
		t.Fatal("cross-session replay accepted")
	}
	wrong = inv
	wrong.Secret = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	if _, err := wrong.open(v.Key, "key"); err == nil {
		t.Fatal("relay transport token substituted for secret")
	}
	if _, err := inv.verifyKey(v.Key, sshPairMessage{Payload: "different-hello"}, "testuser"); err == nil {
		t.Fatal("host transcript substitution accepted")
	}
}
func TestSSHPairInvitationExpiryAndURI(t *testing.T) {
	v := pairVector(t)
	raw, _ := json.Marshal(v.Invitation)
	now := time.UnixMilli(v.Invitation.Expires - 1000)
	uri := "shinphony://ssh-pair#" + base64.RawURLEncoding.EncodeToString(raw)
	if _, err := parseSSHPairInvitation(uri, now); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{uri + "=", string(raw) + "{}", strings.Replace(string(raw), `"v":1`, `"v":2`, 1)} {
		if _, err := parseSSHPairInvitation(bad, now); err == nil {
			t.Fatalf("invalid invitation accepted")
		}
	}
	if _, err := parseSSHPairInvitation(string(raw), time.UnixMilli(v.Invitation.Expires)); err == nil {
		t.Fatal("expired invitation accepted")
	}
	if _, err := parseSSHPairInvitation(string(raw), now.Add(-10*time.Minute)); err == nil {
		t.Fatal("extended invitation accepted")
	}
}
func TestSSHPairTransportNeverTransmitsPairingSecret(t *testing.T) {
	inv, err := newSSHPairInvitation("command")
	if err != nil {
		t.Fatal(err)
	}
	var bodies []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(raw))
		if strings.Contains(string(raw), inv.Secret) || strings.Contains(r.URL.String(), inv.Secret) || strings.Contains(r.Header.Get("Authorization"), inv.Secret) {
			t.Error("pairing secret transmitted")
		}
		json.NewEncoder(w).Encode(sshPairMailbox{Schema: 1, ID: inv.ID, Expires: inv.Expires})
	}))
	defer server.Close()
	transport := sshPairTransport{origin: server.URL, client: server.Client()}
	if _, err := transport.create(inv); err != nil {
		t.Fatal(err)
	}
	hello, _ := inv.seal("hello", "test")
	if _, err := transport.exchange(inv, "hello", &hello); err != nil {
		t.Fatal(err)
	}
	if len(bodies) != 2 {
		t.Fatal("missing requests")
	}
}
