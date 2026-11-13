//go:build darwin || linux

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const sshPairDomain = "shinphony-ssh-pair-v1"
const sshPairMACDomain = "Shinphony-SSH-Pair-MAC-v1\x00"
const sshPairProofDomain = "Shinphony-SSH-Key-Proof-v1\x00"

type sshPairInvitation struct {
	Version   int    `json:"v"`
	ID        string `json:"id"`
	Secret    string `json:"secret"`
	Expires   int64  `json:"expires"`
	Mode      string `json:"mode"`
	HelloHash string `json:"helloHash,omitempty"`
}
type sshPairMessage struct {
	Payload string `json:"payload"`
	MAC     string `json:"mac"`
	Proof   string `json:"proof,omitempty"`
}
type sshPairMailbox struct {
	Schema  int             `json:"schema"`
	ID      string          `json:"id"`
	Expires int64           `json:"expires"`
	Hello   *sshPairMessage `json:"hello"`
	Key     *sshPairMessage `json:"key"`
	Receipt *sshPairMessage `json:"receipt"`
}

func newSSHPairInvitation(mode string) (sshPairInvitation, error) {
	id, secret := make([]byte, 16), make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		return sshPairInvitation{}, err
	}
	if _, err := rand.Read(secret); err != nil {
		return sshPairInvitation{}, err
	}
	return sshPairInvitation{Version: 1, ID: base64.RawURLEncoding.EncodeToString(id), Secret: base64.RawURLEncoding.EncodeToString(secret), Mode: mode, Expires: time.Now().Add(5 * time.Minute).UnixMilli()}, nil
}

func parseSSHPairInvitation(value string, now time.Time) (sshPairInvitation, error) {
	var invitation sshPairInvitation
	if strings.HasPrefix(value, "shinphony://") {
		uri, err := url.Parse(value)
		if err != nil || uri.Scheme != "shinphony" || uri.Host != "ssh-pair" || uri.Path != "" || uri.RawQuery != "" || uri.User != nil {
			return invitation, errors.New("invalid_ssh_pair_invitation")
		}
		raw, err := base64.RawURLEncoding.DecodeString(uri.Fragment)
		if err != nil {
			return invitation, errors.New("invalid_ssh_pair_invitation")
		}
		value = string(raw)
	}
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.DisallowUnknownFields()
	if len(value) > 2048 || decoder.Decode(&invitation) != nil || decoder.Decode(new(any)) != io.EOF {
		return invitation, errors.New("invalid_ssh_pair_invitation")
	}
	id, e1 := base64.RawURLEncoding.Strict().DecodeString(invitation.ID)
	secret, e2 := base64.RawURLEncoding.Strict().DecodeString(invitation.Secret)
	if invitation.Version != 1 || e1 != nil || e2 != nil || len(id) != 16 || len(secret) != 32 ||
		(invitation.Mode != "qr" && invitation.Mode != "command") || invitation.Expires <= now.UnixMilli() || invitation.Expires > now.Add(5*time.Minute+10*time.Second).UnixMilli() {
		return invitation, errors.New("invalid_ssh_pair_invitation")
	}
	return invitation, nil
}

func (inv sshPairInvitation) key() []byte {
	value, _ := base64.RawURLEncoding.DecodeString(inv.Secret)
	return value
}
func (inv sshPairInvitation) auth(role string) string {
	h := hmac.New(sha256.New, inv.key())
	h.Write([]byte("Shinphony-SSH-Transport-v1\x00" + inv.ID + "\x00" + role))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
func (inv sshPairInvitation) seal(kind string, values ...any) (sshPairMessage, error) {
	raw, err := json.Marshal(append([]any{sshPairDomain, kind, inv.ID}, values...))
	if err != nil {
		return sshPairMessage{}, err
	}
	payload := base64.RawURLEncoding.EncodeToString(raw)
	if len(payload) > 1400 {
		return sshPairMessage{}, errors.New("ssh_pair_message_too_large")
	}
	h := hmac.New(sha256.New, inv.key())
	h.Write([]byte(sshPairMACDomain + payload))
	return sshPairMessage{Payload: payload, MAC: base64.RawURLEncoding.EncodeToString(h.Sum(nil))}, nil
}
func (inv sshPairInvitation) open(message sshPairMessage, kind string) ([]json.RawMessage, error) {
	if len(message.Payload) > 1400 {
		return nil, errors.New("ssh_pair_message_invalid")
	}
	h := hmac.New(sha256.New, inv.key())
	h.Write([]byte(sshPairMACDomain + message.Payload))
	mac, err := base64.RawURLEncoding.Strict().DecodeString(message.MAC)
	if err != nil || !hmac.Equal(mac, h.Sum(nil)) {
		return nil, errors.New("ssh_pair_message_unauthenticated")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(message.Payload)
	if err != nil {
		return nil, errors.New("ssh_pair_message_invalid")
	}
	var values []json.RawMessage
	if json.Unmarshal(raw, &values) != nil || len(values) < 3 || string(values[0]) != `"`+sshPairDomain+`"` || string(values[1]) != `"`+kind+`"` || string(values[2]) != `"`+inv.ID+`"` {
		return nil, errors.New("ssh_pair_message_invalid")
	}
	return values[3:], nil
}
func sshPairHash(value string) string {
	hash := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}
func (inv sshPairInvitation) sas(hello, key sshPairMessage) string {
	h := hmac.New(sha256.New, inv.key())
	h.Write([]byte("Shinphony-SSH-SAS-v1\x00" + hello.Payload + "\x00" + key.Payload))
	return fmt.Sprintf("%06d", binary.BigEndian.Uint32(h.Sum(nil)[:4])%1000000)
}
func (inv sshPairInvitation) verifyKey(message sshPairMessage, hello sshPairMessage, username string) (sshKeyRequest, error) {
	values, err := inv.open(message, "key")
	if err != nil {
		return sshKeyRequest{}, err
	}
	var helloHash, id, publicKey, address, user string
	var port int
	if len(values) != 6 || json.Unmarshal(values[0], &helloHash) != nil || json.Unmarshal(values[1], &id) != nil || json.Unmarshal(values[2], &publicKey) != nil || json.Unmarshal(values[3], &address) != nil || json.Unmarshal(values[4], &port) != nil || json.Unmarshal(values[5], &user) != nil ||
		helloHash != sshPairHash(hello.Payload) || !sshKeyID.MatchString(id) || user != username || len(address) < 1 || len(address) > 253 || strings.ContainsAny(address, "\x00\r\n ") || port < 1 || port > 65535 {
		return sshKeyRequest{}, errors.New("ssh_pair_key_target_mismatch")
	}
	if _, err := validateP256PublicKey(publicKey); err != nil {
		return sshKeyRequest{}, err
	}
	blob, _ := base64.StdEncoding.DecodeString(strings.Split(publicKey, " ")[1])
	x, y := elliptic.Unmarshal(elliptic.P256(), blob[len(blob)-65:])
	signature, err := base64.RawURLEncoding.Strict().DecodeString(message.Proof)
	hash := sha256.Sum256([]byte(sshPairProofDomain + message.Payload))
	if err != nil || len(signature) != 64 || !ecdsa.Verify(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, hash[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		return sshKeyRequest{}, errors.New("ssh_pair_key_proof_invalid")
	}
	return sshKeyRequest{ID: id, PublicKey: publicKey}, nil
}

type sshPairTransport struct {
	origin string
	client *http.Client
}

func productionSSHPairTransport() sshPairTransport {
	return sshPairTransport{origin: "https://notify.potafree.net/production", client: &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}}
}
func (transport sshPairTransport) request(path, auth string, body any) (sshPairMailbox, error) {
	var reply sshPairMailbox
	raw, err := json.Marshal(body)
	if err != nil {
		return reply, err
	}
	request, err := http.NewRequest(http.MethodPost, transport.origin+path, bytes.NewReader(raw))
	if err != nil {
		return reply, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "ShinphonyHook-SSH-Pair/1")
	if auth != "" {
		request.Header.Set("Authorization", "Bearer "+auth)
	}
	response, err := transport.client.Do(request)
	if err != nil {
		return reply, errors.New("ssh_pair_network_unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return reply, errors.New("ssh_pair_service_unavailable")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 8193))
	if err != nil || len(data) > 8192 || json.Unmarshal(data, &reply) != nil || reply.Schema != 1 {
		return reply, errors.New("ssh_pair_response_invalid")
	}
	return reply, nil
}
func (transport sshPairTransport) create(inv sshPairInvitation) (sshPairMailbox, error) {
	hash := func(value string) string { raw := sha256.Sum256([]byte(value)); return hex.EncodeToString(raw[:]) }
	return transport.request("/v1/ssh-pair/create", "", map[string]any{"id": inv.ID, "mode": inv.Mode, "hostHash": hash(inv.auth("host")), "phoneHash": hash(inv.auth("phone"))})
}
func (transport sshPairTransport) exchange(inv sshPairInvitation, kind string, message *sshPairMessage) (sshPairMailbox, error) {
	body := map[string]any{"id": inv.ID}
	if message != nil {
		body["kind"] = kind
		body["message"] = message
	}
	return transport.request("/v1/ssh-pair/host", inv.auth("host"), body)
}
