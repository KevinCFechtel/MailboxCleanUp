// Package secrets keeps an age identity in process memory, never on disk.
package secrets

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"sync"

	"filippo.io/age"
)

const MaxFileSize = 1024 * 1024

var ErrLocked = errors.New("service is locked")

type Credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Credentials struct {
	Accounts map[string]Credential `json:"accounts"`
}

type Store struct {
	mu       sync.RWMutex
	path     string
	accounts []string
	identity *age.X25519Identity
}

func New(path string, accounts []string) *Store {
	return &Store{path: path, accounts: accounts}
}

func (s *Store) Unlock(key string) error {
	id, err := age.ParseX25519Identity(strings.TrimSpace(key))
	if err != nil {
		return errors.New("invalid age private key")
	}
	if _, err := s.read(id); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.identity = id
	return nil
}

func (s *Store) Lock() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.identity = nil
}

func (s *Store) Unlocked() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.identity != nil
}

// Read reloads the encrypted file on every job, allowing credential rotation.
func (s *Store) Read() (Credentials, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.identity == nil {
		return Credentials{}, ErrLocked
	}
	return s.read(s.identity)
}

func (s *Store) read(id *age.X25519Identity) (Credentials, error) {
	var c Credentials
	f, err := os.Open(s.path)
	if err != nil {
		return c, errors.New("cannot open encrypted credentials")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > MaxFileSize {
		return c, errors.New("encrypted credentials must be a regular file, at most 1 MiB")
	}
	r, err := age.Decrypt(io.LimitReader(f, MaxFileSize), id)
	if err != nil {
		return c, errors.New("cannot decrypt credentials")
	}
	plain, err := io.ReadAll(io.LimitReader(r, MaxFileSize+1))
	if err != nil || len(plain) > MaxFileSize {
		return c, errors.New("cannot read decrypted credentials")
	}
	defer clear(plain)
	d := json.NewDecoder(bytes.NewReader(plain))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return Credentials{}, errors.New("invalid encrypted credential structure")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return Credentials{}, errors.New("credentials must contain one JSON object")
	}
	for _, name := range s.accounts {
		credential, ok := c.Accounts[name]
		if !ok || credential.Username == "" || credential.Password == "" {
			return Credentials{}, errors.New("credentials missing for a configured account")
		}
	}
	return c, nil
}

func Encrypt(w io.Writer, c Credentials, recipient age.Recipient) error {
	plain, err := json.Marshal(c)
	if err != nil {
		return errors.New("cannot encode credentials")
	}
	defer clear(plain)
	encrypted, err := age.Encrypt(w, recipient)
	if err != nil {
		return errors.New("cannot initialize encryption")
	}
	if _, err := encrypted.Write(plain); err != nil {
		return errors.New("cannot write encrypted credentials")
	}
	return encrypted.Close()
}
