package control

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/KevinCFechtel/MailboxCleanUp/internal/job"
	"github.com/KevinCFechtel/MailboxCleanUp/internal/secrets"
)

func TestLockedControlAPI(t *testing.T) {
	service := job.NewService(&job.Engine{Store: secrets.New("not-present", nil)}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	handler := Handler(context.Background(), service)
	for _, tc := range []struct {
		method, path string
		status       int
	}{
		{"GET", "/status", http.StatusOK},
		{"POST", "/run", http.StatusConflict},
		{"POST", "/lock", http.StatusNoContent},
		{"POST", "/unlock", http.StatusBadRequest},
		{"GET", "/lock", http.StatusMethodNotAllowed},
	} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != tc.status {
			t.Fatalf("%s %s: %d", tc.method, tc.path, w.Code)
		}
	}
}

func TestSocketPermissionsAndExistingPathProtection(t *testing.T) {
	// Use a short relative path to fit macOS's Unix socket path length limit.
	dir, err := os.MkdirTemp(".", ".socket-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(dir) })
	path := filepath.Join(dir, "ctl.sock")
	listener, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("socket permissions are not private")
	}
	if other, err := Listen(path); err == nil {
		other.Close()
		t.Fatal("live socket was replaced")
	}
}
