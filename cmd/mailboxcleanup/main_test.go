package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/KevinCFechtel/MailboxCleanUp/internal/config"
	"github.com/KevinCFechtel/MailboxCleanUp/internal/control"
	"github.com/KevinCFechtel/MailboxCleanUp/internal/job"
	"github.com/KevinCFechtel/MailboxCleanUp/internal/secrets"
)

func TestPrivateOutputNeverOverwrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private")
	write := func(w io.Writer) error { _, err := io.WriteString(w, "original"); return err }
	if err := writePrivate(path, write); err != nil {
		t.Fatal(err)
	}
	if writePrivate(path, func(w io.Writer) error { _, err := io.WriteString(w, "replacement"); return err }) == nil {
		t.Fatal("existing file overwritten")
	}
	data, _ := os.ReadFile(path)
	info, _ := os.Stat(path)
	if string(data) != "original" || info.Mode().Perm() != 0600 {
		t.Fatal("private file not preserved")
	}
}

func TestServeLockedUnlockRunLockAndStopWithWebDisabled(t *testing.T) {
	dir, err := os.MkdirTemp(".", ".daemon-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) }) // Only this test's dedicated directory.
	id, _ := age.GenerateX25519Identity()
	var encrypted bytes.Buffer
	_ = secrets.Encrypt(&encrypted, secrets.Credentials{}, id.Recipient())
	encryptedPath := filepath.Join(dir, "credentials.age")
	_ = os.WriteFile(encryptedPath, encrypted.Bytes(), 0600)
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	c := config.Config{
		CredentialsFile: encryptedPath, Socket: filepath.Join(dir, "control.sock"),
		Schedule: "0 0 1 1 *", Timezone: "UTC", DryRun: true, JobTimeout: "1s", CommandTimeout: "1s",
		// A disabled UI must not read token files or attempt to bind a web port.
		Web: config.Web{Enabled: false, Listen: occupied.Addr().String(), TokenFile: "nonexistent"},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() { finished <- serve(ctx, newEngine(c)) }()
	client := control.Client(c.Socket)
	defer client.CloseIdleConnections()
	deadline := time.After(5 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	var response *http.Response
	for response == nil {
		select {
		case err := <-finished:
			t.Fatalf("daemon exited early: %v", err)
		case <-deadline:
			t.Fatal("daemon did not start")
		case <-ticker.C:
			response, _ = client.Get("http://localhost/status")
		}
	}
	var status job.Status
	if err := json.NewDecoder(response.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if status.Unlocked || status.Running || !status.DryRun {
		t.Fatal("unsafe initial status")
	}
	post := func(path, body string, expected int) {
		t.Helper()
		r, err := client.Post("http://localhost/"+path, "text/plain", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		_, _ = io.Copy(io.Discard, r.Body)
		if r.StatusCode != expected {
			t.Fatalf("%s: got %d", path, r.StatusCode)
		}
	}
	post("run", "", http.StatusConflict)
	post("unlock", id.String(), http.StatusNoContent)
	post("run", "", http.StatusAccepted)
	post("lock", "", http.StatusNoContent)
	client.CloseIdleConnections()
	cancel()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("daemon did not shut down")
	}
	if _, err := os.Stat(c.Socket); !os.IsNotExist(err) {
		t.Fatal("control socket not cleaned up")
	}
}

func TestCommandsRejectKeyArgumentsAndUnknownCommands(t *testing.T) {
	for _, args := range [][]string{
		nil, {"unknown"}, {"unlock", "--key", "never-pass-secrets-here"},
		{"serve", "--key-stdin"}, {"status", "--key-stdin"},
		{"credentials"}, {"web-token", "unexpected"},
	} {
		if run(context.Background(), args) == nil {
			t.Fatalf("accepted invalid command: %v", args)
		}
	}
}
