package main

// Test keys shared by the Unix and Windows suites: a valid P-256 SSH key and the
// request that installs it.

import (
	"crypto/elliptic"
	"encoding/base64"
	"encoding/binary"
)

func testP256SSHKey() string {
	field := func(b []byte) []byte {
		r := make([]byte, 4+len(b))
		binary.BigEndian.PutUint32(r, uint32(len(b)))
		copy(r[4:], b)
		return r
	}
	curve := elliptic.P256()
	point := elliptic.Marshal(curve, curve.Params().Gx, curve.Params().Gy)
	wire := append(field([]byte("ecdsa-sha2-nistp256")), field([]byte("nistp256"))...)
	wire = append(wire, field(point)...)
	return "ecdsa-sha2-nistp256 " + base64.StdEncoding.EncodeToString(wire)
}
func keyRequest() sshKeyRequest {
	return sshKeyRequest{ID: "se-p256:12345678-1234-1234-1234-123456789abc", PublicKey: testP256SSHKey()}
}
