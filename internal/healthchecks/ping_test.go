package healthchecks

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KevinCFechtel/MailboxCleanUp/internal/job"
)

const checkID = "00000000-0000-0000-0000-000000000001"

func urlFile(t *testing.T, value string) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "healthchecks-url")
	if err := os.WriteFile(file, []byte(value+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return file
}

func TestPingOnlySendsAggregateCounts(t *testing.T) {
	var calls atomic.Int32
	want := job.Counts{Matched: 42, Archived: 30, Deleted: 12}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/"+checkID || r.ContentLength <= 0 || r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/json" {
			t.Error("unexpected request or data sent to healthchecks")
		}
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		var fields map[string]json.RawMessage
		var got job.Counts
		if json.Unmarshal(data, &fields) != nil || len(fields) != 4 || json.Unmarshal(data, &got) != nil || got != want {
			t.Error("payload must contain only the expected counts and dry-run flag")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	p := New(urlFile(t, server.URL+"/"+checkID), time.Second, false)
	p.client = server.Client() // Trust only this test server's certificate.
	if err := p.Ping(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("expected exactly one success ping")
	}
}

func TestNonSuccessAndRedirectsAreNotAccepted(t *testing.T) {
	for _, status := range []int{http.StatusFound, http.StatusUnauthorized, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Location", "/"+checkID)
				w.WriteHeader(status)
			}))
			defer server.Close()
			endpoint := server.URL + "/" + checkID
			p := New(urlFile(t, endpoint), time.Second, false)
			client := server.Client()
			client.CheckRedirect = p.client.CheckRedirect
			p.client = client
			err := p.Ping(context.Background(), job.Counts{})
			if err == nil || strings.Contains(err.Error(), endpoint) || strings.Contains(err.Error(), checkID) {
				t.Fatal("unsuccessful ping accepted or secret URL leaked")
			}
			if calls.Load() != 1 {
				t.Fatal("redirect followed or ping retried")
			}
		})
	}
}

func TestInvalidEndpointsAndPermissionsAreRejected(t *testing.T) {
	for _, endpoint := range []string{
		"http://hc-ping.com/" + checkID,
		"https://user:password@hc-ping.com/" + checkID,
		"https://hc-ping.com/" + checkID + "/start",
		"https://hc-ping.com/" + checkID + "/fail",
		"https://hc-ping.com/" + checkID + "/log",
		"https://hc-ping.com/" + checkID + "/0",
		"https://hc-ping.com/" + checkID + "/",
		"https://hc-ping.com/" + checkID + "?status=fail",
		"https://hc-ping.com/" + checkID + "#fragment",
		"https://hc-ping.com/not-a-uuid",
	} {
		for _, allow := range []bool{false, true} {
			if _, err := readURL(urlFile(t, endpoint), allow); err == nil {
				t.Error("invalid success endpoint accepted")
			}
		}
	}
	file := urlFile(t, "https://hc-ping.com/"+checkID)
	if err := os.Chmod(file, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readURL(file, false); err == nil {
		t.Fatal("world-readable ping URL accepted")
	}
}

func TestNetworkErrorsAreRedactedAndCancellationSendsNothing(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
	}))
	defer server.Close()
	endpoint := server.URL + "/" + checkID
	p := New(urlFile(t, endpoint), time.Second, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := p.Ping(ctx, job.Counts{})
	if err == nil || strings.Contains(err.Error(), checkID) || strings.Contains(err.Error(), endpoint) || calls.Load() != 0 {
		t.Fatal("cancelled ping sent a request or leaked URL")
	}
	// Production transport must reject untrusted server certificates.
	if err := p.Ping(context.Background(), job.Counts{}); err == nil || calls.Load() != 0 {
		t.Fatal("untrusted TLS server accepted")
	}
}

func TestURLIsReloadedForEveryPing(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
	}))
	defer server.Close()
	file := urlFile(t, server.URL+"/"+checkID)
	p := New(file, time.Second, false)
	p.client = server.Client()
	if err := p.Ping(context.Background(), job.Counts{}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("invalid rotated URL"), 0600); err != nil {
		t.Fatal(err)
	}
	if p.Ping(context.Background(), job.Counts{}) == nil || calls.Load() != 1 {
		t.Fatal("URL was cached instead of being reloaded")
	}
}

func TestPingURLFilePermissions(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
	}))
	defer server.Close()
	for _, mode := range []os.FileMode{0400, 0600, 0640, 0644, 0660, 0666} {
		for _, allow := range []bool{false, true} {
			t.Run(fmt.Sprintf("%04o/allow=%t", mode, allow), func(t *testing.T) {
				file := urlFile(t, server.URL+"/"+checkID)
				if err := os.Chmod(file, mode); err != nil {
					t.Fatal(err)
				}
				p := New(file, time.Second, allow)
				p.client = server.Client()
				before := calls.Load()
				err := p.Ping(context.Background(), job.Counts{})
				if !allow && mode&0077 != 0 {
					if err == nil || !strings.Contains(err.Error(), "healthchecks.allow_insecure_url_permissions") || calls.Load() != before {
						t.Fatalf("expected permission error without a ping, got %v", err)
					}
					return
				}
				if err != nil || calls.Load() != before+1 {
					t.Fatalf("expected successful ping, got %v", err)
				}
			})
		}
	}
}

func TestInvalidURLFileRegardlessOfPermissionsOption(t *testing.T) {
	for _, allow := range []bool{false, true} {
		for _, kind := range []string{"missing", "directory", "oversized", "empty"} {
			t.Run(fmt.Sprintf("%s/allow=%t", kind, allow), func(t *testing.T) {
				file := filepath.Join(t.TempDir(), "healthchecks-url")
				switch kind {
				case "directory":
					if err := os.Mkdir(file, 0700); err != nil {
						t.Fatal(err)
					}
				case "oversized":
					if err := os.WriteFile(file, []byte(strings.Repeat("x", 4097)), 0600); err != nil {
						t.Fatal(err)
					}
				case "empty":
					if err := os.WriteFile(file, nil, 0600); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := readURL(file, allow); err == nil {
					t.Fatal("invalid URL file accepted")
				}
			})
		}
	}
}
