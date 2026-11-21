package web

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/KevinCFechtel/MailboxCleanUp/internal/config"
	"github.com/KevinCFechtel/MailboxCleanUp/internal/job"
	"github.com/KevinCFechtel/MailboxCleanUp/internal/secrets"
)

const testToken = "test-token-with-at-least-32-characters"

func uiFixture(t *testing.T) (*UI, string) {
	t.Helper()
	return uiFixtureWithLogs(t, io.Discard)
}

func uiFixtureWithLogs(t *testing.T, logs io.Writer) (*UI, string) {
	t.Helper()
	dir := t.TempDir()
	id, _ := age.GenerateX25519Identity()
	var buf bytes.Buffer
	_ = secrets.Encrypt(&buf, secrets.Credentials{Accounts: map[string]secrets.Credential{"personal": {Username: "user", Password: "mail-password"}}}, id.Recipient())
	path := filepath.Join(dir, "credentials.age")
	_ = os.WriteFile(path, buf.Bytes(), 0600)
	tokenPath := filepath.Join(dir, "token")
	_ = os.WriteFile(tokenPath, []byte(testToken), 0600)
	engine := &job.Engine{Config: config.Config{JobTimeout: "1s"}, Store: secrets.New(path, []string{"personal"})}
	service := job.NewService(engine, slog.New(slog.NewTextHandler(logs, nil)))
	ui, err := New(context.Background(), config.Web{TokenFile: tokenPath, SecureCookies: true}, service)
	if err != nil {
		t.Fatal(err)
	}
	return ui, id.String()
}

func request(handler http.Handler, method, path string, values url.Values, cookie *http.Cookie, origin string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(values.Encode()))
	if method == http.MethodPost {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func logIn(t *testing.T, handler http.Handler) (*http.Cookie, string) {
	t.Helper()
	w := request(handler, "POST", "/login", url.Values{"token": {testToken}}, nil, "")
	if w.Code != http.StatusSeeOther {
		t.Fatalf("login failed: %d", w.Code)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("unsafe session cookie")
	}
	w = request(handler, "GET", "/", nil, cookies[0], "")
	match := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(w.Body.String())
	if len(match) != 2 {
		t.Fatal("missing CSRF field")
	}
	return cookies[0], match[1]
}

func TestPagesRenderInEnglish(t *testing.T) {
	ui, _ := uiFixture(t)
	cases := []struct {
		name string
		view view
		want []string
	}{
		{
			name: "sign-in",
			want: []string{"Sign in", "Access token", "The web access token is separate from the decryption key."},
		},
		{
			name: "locked",
			view: view{Authenticated: true, Status: job.Status{DryRun: true}},
			want: []string{"Service status", "Locked", "Dry-run enabled: no changes", "External / manual triggers only",
				"Unlock mailbox access", "Private age key", "Run job now", "Lock service", "Sign out"},
		},
		{
			name: "running-live",
			view: view{Authenticated: true, Status: job.Status{
				Unlocked: true, Running: true, Schedule: "0 3 * * *", Timezone: "Europe/Berlin",
			}},
			want: []string{"Unlocked", "Job running", "Live mode enabled: rules modify the mailbox", "Schedule: 0 3 * * *",
				"Signing out does not lock the service."},
		},
		{
			name: "successful-dry-run",
			view: view{Authenticated: true, Status: job.Status{Last: &job.Report{Success: true, DryRun: true}}},
			want: []string{"Last job", "Successful", "Dry-run: no changes", "End:", "Account / Rule", "Matches", "Confirmed UIDs", "Error"},
		},
		{
			name: "failed-live",
			view: view{Authenticated: true, Status: job.Status{Last: &job.Report{Error: "message search failed"}}},
			want: []string{"Last job", "Failed", "Live mode", "message search failed"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			ui.render(w, tc.view)
			body := w.Body.String()
			for _, text := range append(tc.want, `<html lang="en">`, "No message content. No external scripts. No analytics services.") {
				if !strings.Contains(body, text) {
					t.Errorf("missing English page text %q", text)
				}
			}
		})
	}
}

func TestSignInAndUnlockFailuresAreEnglish(t *testing.T) {
	ui, _ := uiFixture(t)
	handler := ui.Handler()
	w := request(handler, "POST", "/login", url.Values{"token": {"wrong"}}, nil, "")
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "Sign-in failed.") {
		t.Fatal("missing English sign-in failure message")
	}
	cookie, csrf := logIn(t, handler)
	w = request(handler, "POST", "/unlock", url.Values{"csrf": {csrf}, "key": {"invalid"}}, cookie, "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Unlock failed: invalid age private key.") {
		t.Fatal("missing English unlock failure message")
	}
	if ui.service.Status().Unlocked {
		t.Fatal("invalid key unlocked service")
	}
}

func TestUnlockDiagnosticsAreLoggedWithoutSecrets(t *testing.T) {
	for _, kind := range []string{"invalid key", "wrong key", "missing file", "invalid file", "missing account", "invalid structure"} {
		t.Run(kind, func(t *testing.T) {
			var logs bytes.Buffer
			ui, key := uiFixtureWithLogs(t, &logs)
			path := filepath.Join(filepath.Dir(ui.config.TokenFile), "credentials.age")
			want := ""
			switch kind {
			case "invalid key":
				key = "invalid-private-key-input"
				want = "invalid age private key"
			case "wrong key":
				other, err := age.GenerateX25519Identity()
				if err != nil {
					t.Fatal(err)
				}
				key = other.String()
				want = "cannot decrypt credentials; key does not match or encrypted file is invalid"
			case "missing file":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				want = "encrypted credentials file not found; check credentials_file and container mount"
			case "invalid file":
				if err := os.WriteFile(path, []byte("invalid-encrypted-file-content"), 0600); err != nil {
					t.Fatal(err)
				}
				want = "cannot decrypt credentials; key does not match or encrypted file is invalid"
			case "missing account", "invalid structure":
				id, err := age.ParseX25519Identity(key)
				if err != nil {
					t.Fatal(err)
				}
				var encrypted bytes.Buffer
				w, err := age.Encrypt(&encrypted, id.Recipient())
				if err != nil {
					t.Fatal(err)
				}
				plain := `{"accounts":{"other":{"username":"private-username","password":"mail-password"}}}`
				want = "credentials missing for a configured account; check account names and stored username/password"
				if kind == "invalid structure" {
					plain = `{"private-username":"mail-password"}`
					want = "invalid encrypted credential structure"
				}
				if _, err := io.WriteString(w, plain); err != nil {
					t.Fatal(err)
				}
				if err := w.Close(); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, encrypted.Bytes(), 0600); err != nil {
					t.Fatal(err)
				}
			}
			handler := ui.Handler()
			cookie, csrf := logIn(t, handler)
			w := request(handler, "POST", "/unlock", url.Values{"csrf": {csrf}, "key": {key}}, cookie, "")
			if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Unlock failed: "+want+".") {
				t.Fatalf("missing unlock diagnostic: %s", w.Body.String())
			}
			if !strings.Contains(logs.String(), "unlock failed") || !strings.Contains(logs.String(), want) {
				t.Fatalf("missing unlock log: %s", logs.String())
			}
			if ui.service.Status().Unlocked {
				t.Fatal("failed unlock changed state")
			}
			for _, secret := range []string{key, testToken, csrf, cookie.Value, "private-username", "mail-password", "invalid-encrypted-file-content"} {
				if strings.Contains(logs.String(), secret) {
					t.Fatal("secret leaked into log")
				}
			}
			for _, secret := range []string{key, testToken, cookie.Value, "private-username", "mail-password", "invalid-encrypted-file-content"} {
				if strings.Contains(w.Body.String(), secret) {
					t.Fatal("secret reflected into page")
				}
			}
		})
	}
}

func TestUnlockLockAndLogout(t *testing.T) {
	var logs bytes.Buffer
	ui, key := uiFixtureWithLogs(t, &logs)
	handler := ui.Handler()
	cookie, csrf := logIn(t, handler)
	w := request(handler, "POST", "/unlock", url.Values{"csrf": {csrf}, "key": {key}}, cookie, "")
	if w.Code != http.StatusOK || !ui.service.Status().Unlocked {
		t.Fatalf("unlock failed: %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Unlocked. Scheduled jobs can now run.") {
		t.Fatal("missing English unlock message")
	}
	if !strings.Contains(logs.String(), "service unlocked") || strings.Contains(logs.String(), key) || strings.Contains(logs.String(), "mail-password") {
		t.Fatal("missing or unsafe unlock success log")
	}
	if strings.Contains(w.Body.String(), key) || strings.Contains(w.Body.String(), "mail-password") {
		t.Fatal("secret reflected into page")
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("missing security headers")
	}
	w = request(handler, "POST", "/logout", url.Values{"csrf": {csrf}}, cookie, "")
	if w.Code != http.StatusSeeOther || !ui.service.Status().Unlocked {
		t.Fatal("logout must not lock cron jobs")
	}
	w = request(handler, "POST", "/lock", url.Values{"csrf": {csrf}}, cookie, "")
	if w.Code != http.StatusUnauthorized {
		t.Fatal("invalidated session still works")
	}
	cookie, csrf = logIn(t, handler)
	w = request(handler, "POST", "/lock", url.Values{"csrf": {csrf}}, cookie, "")
	if w.Code != http.StatusOK || ui.service.Status().Unlocked {
		t.Fatal("web lock failed")
	}
	if !strings.Contains(w.Body.String(), "Locked. Any running job will be cancelled.") {
		t.Fatal("missing English lock message")
	}
}

func TestAuthenticationCSRFAndOriginRequired(t *testing.T) {
	ui, key := uiFixture(t)
	h := ui.Handler()
	values := url.Values{"key": {key}}
	if w := request(h, "POST", "/unlock", values, nil, ""); w.Code != http.StatusUnauthorized {
		t.Fatal("anonymous unlock allowed")
	}
	cookie, csrf := logIn(t, h)
	if w := request(h, "POST", "/unlock", values, cookie, ""); w.Code != http.StatusForbidden {
		t.Fatal("missing CSRF accepted")
	}
	values.Set("csrf", csrf)
	if w := request(h, "POST", "/unlock", values, cookie, "https://evil.example"); w.Code != http.StatusForbidden {
		t.Fatal("cross-origin unlock accepted")
	}
	if ui.service.Status().Unlocked {
		t.Fatal("rejected requests changed state")
	}
	// Mutations cannot be induced with a GET request.
	if w := request(h, "GET", "/unlock", nil, cookie, ""); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("unexpected GET status: %d", w.Code)
	}
}

func TestRateLimitsAndExpiry(t *testing.T) {
	ui, _ := uiFixture(t)
	h := ui.Handler()
	cookie, _ := logIn(t, h)
	ui.mu.Lock()
	for hash, s := range ui.sessions {
		s.Expires = time.Now().Add(-time.Second)
		ui.sessions[hash] = s
	}
	ui.mu.Unlock()
	if w := request(h, "POST", "/lock", nil, cookie, ""); w.Code != http.StatusUnauthorized {
		t.Fatal("expired session accepted")
	}
	for range 4 {
		w := request(h, "POST", "/login", url.Values{"token": {"bad"}}, nil, "")
		if w.Code != http.StatusUnauthorized {
			t.Fatal("unexpected rate limiting threshold")
		}
	}
	if w := request(h, "POST", "/login", url.Values{"token": {testToken}}, nil, ""); w.Code != http.StatusTooManyRequests {
		t.Fatal("login rate limit missing")
	}
}

func TestOversizedInputAndUnsafeTokenFile(t *testing.T) {
	ui, _ := uiFixture(t)
	h := ui.Handler()
	w := request(h, "POST", "/login", url.Values{"token": {strings.Repeat("x", 10000)}}, nil, "")
	if w.Code != http.StatusBadRequest {
		t.Fatal("oversized login accepted")
	}
	if err := os.Chmod(ui.config.TokenFile, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := New(context.Background(), ui.config, ui.service); err == nil {
		t.Fatal("world-readable token file accepted")
	}
}

func TestTokenFilePermissions(t *testing.T) {
	for _, mode := range []os.FileMode{0400, 0600, 0640, 0644, 0660, 0666} {
		for _, allow := range []bool{false, true} {
			t.Run(fmt.Sprintf("%04o/allow=%t", mode, allow), func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "token")
				if err := os.WriteFile(path, []byte(testToken), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, mode); err != nil {
					t.Fatal(err)
				}
				ui, err := New(context.Background(), config.Web{
					TokenFile: path, AllowInsecureTokenPermissions: allow, SecureCookies: true,
				}, nil)
				if !allow && mode&0077 != 0 {
					if err == nil || !strings.Contains(err.Error(), "web.allow_insecure_token_permissions") {
						t.Fatalf("expected actionable permission error, got %v", err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				w := request(ui.Handler(), "POST", "/login", url.Values{"token": {testToken}}, nil, "")
				if w.Code != http.StatusSeeOther {
					t.Fatalf("login failed: %d", w.Code)
				}
				w = request(ui.Handler(), "POST", "/login", url.Values{"token": {"wrong"}}, nil, "")
				if w.Code != http.StatusUnauthorized {
					t.Fatal("invalid token accepted")
				}
			})
		}
	}
}

func TestInvalidTokenFileRegardlessOfPermissionsOption(t *testing.T) {
	for _, allow := range []bool{false, true} {
		for _, kind := range []string{"missing", "directory", "oversized", "short", "empty"} {
			t.Run(fmt.Sprintf("%s/allow=%t", kind, allow), func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "token")
				var want string
				switch kind {
				case "missing":
					want = "cannot stat web token file"
				case "directory":
					if err := os.Mkdir(path, 0700); err != nil {
						t.Fatal(err)
					}
					want = "must be a regular file"
				default:
					var content string
					switch kind {
					case "oversized":
						content, want = strings.Repeat("x", 4097), "at most 4096 bytes"
					case "short":
						content, want = strings.Repeat("x", 31), "at least 32 characters"
					case "empty":
						content, want = "", "at least 32 characters"
					}
					if err := os.WriteFile(path, []byte(content), 0600); err != nil {
						t.Fatal(err)
					}
				}
				_, err := New(context.Background(), config.Web{
					TokenFile: path, AllowInsecureTokenPermissions: allow,
				}, nil)
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Fatalf("expected %q error, got %v", want, err)
				}
			})
		}
	}
}
