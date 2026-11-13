package main

// Private notifications: the notification text is sealed to the phone before it
// leaves this machine. The relay receives the category, an opaque hostRef and
// the envelope, and can only build a generic alert; the Notification Service
// Extension on the phone opens the envelope. See
// docs/research/private-notifications-and-lockscreen-approval-20261113.md § C.
import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	e2eVersion   = 1
	e2eDomain    = "shinphony-notify-v1"
	e2eHostRefDo = "shinphony-hostref-v1"
	// The relay rejects a larger envelope; the sender trims until it fits.
	e2eMaxEnvelope = 2800
	e2eKeyBytes    = 32
	e2eNonceBytes  = 12
	// Lines are the terminal preview the Live Activity shows. Bounded like the
	// context projection that carries them today.
	e2eMaxLines     = 6
	e2eMaxLineBytes = 700
)

// e2eKey is the phone's public key for one notification pairing, as sent in the
// pairing JSON over the verified SSH connection.
type e2eKey struct {
	V   int    `json:"v"`
	Pub string `json:"pub"`
}

// validE2EPublicKey accepts only a canonical base64url X25519 public key.
func validE2EPublicKey(value string) bool {
	if len(value) != 43 {
		return false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(raw) == e2eKeyBytes
}

func e2ePublicKey(value string) ([]byte, error) {
	if !validE2EPublicKey(value) {
		return nil, errors.New("invalid_e2e_key")
	}
	raw, _ := base64.RawURLEncoding.Strict().DecodeString(value)
	return raw, nil
}

// e2eHostRef names one notification pairing to the relay without naming the
// host. The phone resolves it to the host's name through its own map.
func e2eHostRef(profile string) string {
	sum := sha256.Sum256([]byte(e2eHostRefDo + profile))
	return base64.RawURLEncoding.EncodeToString(sum[:])[:22]
}

func e2eAAD(hostRef string) []byte { return []byte(e2eDomain + hostRef) }

// e2eEnvelope is the wire form the relay passes through untouched.
type e2eEnvelope struct {
	V   int    `json:"v"`
	EPK string `json:"epk"`
	N   string `json:"n"`
	CT  string `json:"ct"`
}

// e2eDeriveKey is HKDF-SHA256(shared, salt = ephPub ‖ phonePub, info = domain).
func e2eDeriveKey(shared, ephPub, phonePub []byte) ([]byte, error) {
	salt := make([]byte, 0, len(ephPub)+len(phonePub))
	salt = append(append(salt, ephPub...), phonePub...)
	key := make([]byte, e2eKeyBytes)
	if _, err := io.ReadFull(hkdf.New(sha256.New, shared, salt, []byte(e2eDomain)), key); err != nil {
		return nil, errors.New("e2e_key_derivation_failed")
	}
	return key, nil
}

// e2eSealWith seals with a caller-supplied ephemeral key and nonce, so the test
// vectors are reproducible. Production always uses e2eSeal.
func e2eSealWith(eph *ecdh.PrivateKey, nonce, phonePub []byte, hostRef string, plaintext []byte) (e2eEnvelope, error) {
	if len(nonce) != e2eNonceBytes || len(phonePub) != e2eKeyBytes {
		return e2eEnvelope{}, errors.New("e2e_parameters_invalid")
	}
	phone, err := ecdh.X25519().NewPublicKey(phonePub)
	if err != nil {
		return e2eEnvelope{}, errors.New("invalid_e2e_key")
	}
	shared, err := eph.ECDH(phone)
	if err != nil {
		return e2eEnvelope{}, errors.New("invalid_e2e_key")
	}
	ephPub := eph.PublicKey().Bytes()
	key, err := e2eDeriveKey(shared, ephPub, phonePub)
	if err != nil {
		return e2eEnvelope{}, err
	}
	box, err := chacha20poly1305.New(key)
	if err != nil {
		return e2eEnvelope{}, errors.New("e2e_cipher_unavailable")
	}
	sealed := box.Seal(nil, nonce, plaintext, e2eAAD(hostRef))
	return e2eEnvelope{
		V:   e2eVersion,
		EPK: base64.RawURLEncoding.EncodeToString(ephPub),
		N:   base64.RawURLEncoding.EncodeToString(nonce),
		CT:  base64.RawURLEncoding.EncodeToString(sealed),
	}, nil
}

func e2eSeal(rnd io.Reader, phonePub []byte, hostRef string, plaintext []byte) (e2eEnvelope, error) {
	eph, err := ecdh.X25519().GenerateKey(rnd)
	if err != nil {
		return e2eEnvelope{}, errors.New("e2e_ephemeral_key_failed")
	}
	nonce := make([]byte, e2eNonceBytes)
	if _, err = io.ReadFull(rnd, nonce); err != nil {
		return e2eEnvelope{}, errors.New("e2e_nonce_failed")
	}
	return e2eSealWith(eph, nonce, phonePub, hostRef, plaintext)
}

// e2ePlaintext is the sealed content: the detail fields the relay would
// otherwise see, plus the terminal lines when there are any.
type e2ePlaintext struct {
	Category   string   `json:"category"`
	Agent      string   `json:"agent,omitempty"`
	Session    string   `json:"session,omitempty"`
	Title      string   `json:"title,omitempty"`
	Body       string   `json:"body,omitempty"`
	Project    string   `json:"project,omitempty"`
	Visibility string   `json:"visibility,omitempty"`
	Lines      []string `json:"lines,omitempty"`
}

func halfRunes(s string) string {
	runes := []rune(s)
	if len(runes) <= 1 {
		return ""
	}
	return strings.TrimSpace(string(runes[:(len(runes)+1)/2]))
}

// trim shortens the longest field, never splitting a UTF-8 sequence, and
// reports whether anything was left to trim.
func (p *e2ePlaintext) trim() bool {
	fields := []*string{&p.Title, &p.Body, &p.Project}
	longest, size := -1, 0
	for i, f := range fields {
		if len(*f) > size {
			longest, size = i, len(*f)
		}
	}
	lines := 0
	if len(p.Lines) > 0 {
		lines = len(strings.Join(p.Lines, "\n"))
	}
	if lines > size {
		longest = len(fields)
	}
	switch {
	case longest < 0:
		return false
	case longest == len(fields):
		if len(p.Lines) == 1 {
			if p.Lines[0] = halfRunes(p.Lines[0]); p.Lines[0] == "" {
				p.Lines = nil
			}
			return true
		}
		p.Lines = p.Lines[:len(p.Lines)-1]
		return true
	default:
		*fields[longest] = halfRunes(*fields[longest])
		return true
	}
}

// e2eSealPlaintext trims until the envelope fits. seal takes the compact
// plaintext JSON and returns the sealed envelope.
func e2eSealPlaintext(seal func([]byte) (e2eEnvelope, error), p *e2ePlaintext) (e2eEnvelope, error) {
	for {
		raw, err := json.Marshal(p)
		if err != nil {
			return e2eEnvelope{}, errors.New("e2e_plaintext_invalid")
		}
		envelope, err := seal(raw)
		if err != nil {
			return e2eEnvelope{}, err
		}
		body, err := json.Marshal(envelope)
		if err != nil {
			return e2eEnvelope{}, errors.New("e2e_envelope_invalid")
		}
		if len(body) <= e2eMaxEnvelope {
			return envelope, nil
		}
		if !p.trim() {
			return e2eEnvelope{}, errors.New("e2e_payload_too_large")
		}
	}
}

// e2ePreviewLines splits the terminal preview into the lines the Live Activity
// shows when the pairing asks for plaintext lines.
func e2ePreviewLines(preview string) []string {
	var lines []string
	for _, line := range strings.Split(preview, "\n") {
		if line = strings.TrimSpace(line); line == "" {
			continue
		}
		lines = append(lines, line)
		if len(lines) == e2eMaxLines {
			break
		}
	}
	if len(lines) == 0 {
		return nil
	}
	if joined := strings.Join(lines, "\n"); len(joined) > e2eMaxLineBytes {
		var out []string
		used := 0
		for _, line := range lines {
			if used+len(line)+1 > e2eMaxLineBytes {
				break
			}
			out, used = append(out, line), used+len(line)+1
		}
		return out
	}
	return lines
}

// e2eFields builds the private part of the relay request: the envelope plus the
// routing the relay still needs. Nothing readable is left in it.
func e2eFields(rnd io.Reader, phonePub []byte, hostRef string, details *eventDetails, context *taskContext) (map[string]any, error) {
	if details == nil || details.Category == "" {
		return nil, errors.New("e2e_details_missing")
	}
	p := &e2ePlaintext{
		Category: details.Category, Agent: details.Agent, Session: details.Session,
		Title: details.Title, Body: details.Body, Project: details.Project,
		Visibility: details.Visibility,
	}
	if context != nil {
		p.Lines = e2ePreviewLines(context.Preview)
	}
	envelope, err := e2eSealPlaintext(func(plaintext []byte) (e2eEnvelope, error) {
		return e2eSeal(rnd, phonePub, hostRef, plaintext)
	}, p)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"category": p.Category,
		"hostRef":  hostRef,
		"e2e":      envelope,
		"silent":   p.Visibility == "silent",
	}, nil
}

// randomReader is the production randomness for sealing.
var randomReader io.Reader = rand.Reader
