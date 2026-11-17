package secrets

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestEncryptedLifecycleAndRotation(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "credentials.age")
	write := func(password string) {
		t.Helper()
		var buf bytes.Buffer
		c := Credentials{Accounts: map[string]Credential{"personal": {Username: "user@example.com", Password: password}}}
		if err := Encrypt(&buf, c, id.Recipient()); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(buf.Bytes(), []byte(password)) {
			t.Fatal("plaintext in encrypted output")
		}
		if err := os.WriteFile(path, buf.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("very-sensitive-password")
	s := New(path, []string{"personal"})
	if _, err := s.Read(); !errors.Is(err, ErrLocked) {
		t.Fatal("must start locked")
	}
	other, _ := age.GenerateX25519Identity()
	if s.Unlock(other.String()) == nil || s.Unlocked() {
		t.Fatal("wrong key unlocked store")
	}
	if err := s.Unlock(id.String()); err != nil {
		t.Fatal(err)
	}
	c, err := s.Read()
	if err != nil || c.Accounts["personal"].Password != "very-sensitive-password" {
		t.Fatal("decryption failed")
	}
	write("rotated-password")
	c, err = s.Read()
	if err != nil || c.Accounts["personal"].Password != "rotated-password" {
		t.Fatal("credentials were not reloaded")
	}
	s.Lock()
	if s.Unlocked() {
		t.Fatal("lock failed")
	}
	if _, err := s.Read(); !errors.Is(err, ErrLocked) {
		t.Fatal(err)
	}
	// A new daemon never inherits an old identity.
	if New(path, []string{"personal"}).Unlocked() {
		t.Fatal("identity was persisted")
	}
}

func TestMissingAccountAndCorruptionAreRedacted(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	var buf bytes.Buffer
	_ = Encrypt(&buf, Credentials{Accounts: map[string]Credential{"other": {Username: "user", Password: "secret"}}}, id.Recipient())
	path := filepath.Join(t.TempDir(), "credentials.age")
	_ = os.WriteFile(path, buf.Bytes(), 0600)
	s := New(path, []string{"personal"})
	if err := s.Unlock(id.String()); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatal("missing account not rejected safely")
	}
	data := buf.Bytes()
	data[len(data)-1] ^= 0xff
	_ = os.WriteFile(path, data, 0600)
	if s.Unlock(id.String()) == nil {
		t.Fatal("tampering not detected")
	}
}
