// Package control exposes the privileged API only through a private Unix socket.
package control

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/KevinCFechtel/MailboxCleanUp/internal/job"
)

const MaxRequest = 8192

func Listen(path string) (net.Listener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
		return nil, errors.New("control socket directory must be a real directory, not writable by group or others")
	}
	// Do not remove a pre-existing path: it might belong to another instance.
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, errors.New("cannot create control socket (another instance or stale socket?)")
	}
	if err := os.Chmod(path, 0600); err != nil {
		listener.Close()
		return nil, err
	}
	return listener, nil
}

func Handler(ctx context.Context, service *job.Service) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(service.Status())
	})
	mux.HandleFunc("POST /unlock", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, MaxRequest)
		key, err := io.ReadAll(r.Body)
		defer clear(key)
		if err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if err := service.Unlock(string(key)); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /lock", func(w http.ResponseWriter, r *http.Request) {
		service.Lock()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /run", func(w http.ResponseWriter, r *http.Request) {
		if err := service.Trigger(ctx); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	})
	return mux
}

func Client(socket string) *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socket)
			},
		},
	}
}
