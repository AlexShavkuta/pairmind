package main

// Unit tests for the security core: key derivation, secret generation and the handshake MAC.
// The agent factory's red/green check depends on `go test ./...`: a fix must ship with a test that
// fails without the fix and passes with it.

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
)

func TestDeriveKeysIsDeterministicAndSeparatesTopicFromPSK(t *testing.T) {
	a, err := deriveKeys("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := deriveKeys("correct horse battery staple")
	if a.rendezvous != b.rendezvous || !bytes.Equal(a.psk, b.psk) {
		t.Fatal("same secret must give the same keys on both peers")
	}
	if !strings.HasPrefix(a.rendezvous, "pairmind/") || len(a.rendezvous) != len("pairmind/")+64 {
		t.Fatalf("rendezvous should be pairmind/<64 hex chars>, got %q", a.rendezvous)
	}
	if len(a.psk) != 32 {
		t.Fatalf("psk should be 32 bytes, got %d", len(a.psk))
	}
	// The public rendezvous string must not reveal the private key.
	if strings.Contains(a.rendezvous, string(a.psk)) || strings.HasSuffix(a.rendezvous, hexOf(a.psk)) {
		t.Fatal("rendezvous must be derived independently of the psk")
	}
}

func TestDifferentSecretsGiveDifferentKeys(t *testing.T) {
	a, _ := deriveKeys("secret-one")
	b, _ := deriveKeys("secret-two")
	if a.rendezvous == b.rendezvous || bytes.Equal(a.psk, b.psk) {
		t.Fatal("different secrets must not share a rendezvous or psk")
	}
}

func TestKeygenFormatAndUniqueness(t *testing.T) {
	shape := regexp.MustCompile(`^[a-z2-7]{4}(-[a-z2-7]{1,4})+$`)
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		k := keygen()
		if !shape.MatchString(k) {
			t.Fatalf("keygen output %q is not dash-grouped lowercase base32", k)
		}
		if got := len(strings.ReplaceAll(k, "-", "")); got != 32 { // 160 bits = 32 base32 chars
			t.Fatalf("keygen should carry 160 bits (32 chars), got %d", got)
		}
		if seen[k] {
			t.Fatal("keygen repeated a secret")
		}
		seen[k] = true
	}
}

func TestMACBindsRoleNonceAndBothPeers(t *testing.T) {
	psk := bytes.Repeat([]byte{7}, 32)
	n := bytes.Repeat([]byte{1}, 32)
	self, other := peer.ID("peer-a"), peer.ID("peer-b")
	base := mac(psk, "initiator", n, self, other)
	if base != mac(psk, "initiator", n, self, other) {
		t.Fatal("mac must be deterministic")
	}
	variants := map[string]string{
		"role":       mac(psk, "responder", n, self, other),
		"nonce":      mac(psk, "initiator", bytes.Repeat([]byte{2}, 32), self, other),
		"peer order": mac(psk, "initiator", n, other, self),
		"psk":        mac(bytes.Repeat([]byte{8}, 32), "initiator", n, self, other),
		"other peer": mac(psk, "initiator", n, self, peer.ID("peer-c")),
	}
	for what, v := range variants {
		if v == base {
			t.Fatalf("changing the %s must change the mac (replay protection)", what)
		}
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return string(out)
}
