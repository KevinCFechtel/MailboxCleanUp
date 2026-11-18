// Package web implements the optional, token-authenticated unlock interface.
package web

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/KevinCFechtel/MailboxCleanUp/internal/config"
	"github.com/KevinCFechtel/MailboxCleanUp/internal/control"
	"github.com/KevinCFechtel/MailboxCleanUp/internal/job"
)

const sessionTTL = 15 * time.Minute
const cookieName = "mailboxcleanup_session"

type session struct {
	CSRF    string
	Expires time.Time
}

type limiter struct {
	start time.Time
	count int
}

func (l *limiter) allow(now time.Time) bool {
	if now.Sub(l.start) >= time.Minute {
		l.start, l.count = now, 0
	}
	l.count++
	return l.count <= 5
}

type UI struct {
	service *job.Service
	ctx     context.Context
	config  config.Web
	token   [32]byte
	mu      sync.Mutex
	// Only a hash of the session cookie is kept server-side.
	sessions map[[32]byte]session
	login    limiter
	unlock   limiter
}

func New(ctx context.Context, c config.Web, service *job.Service) (*UI, error) {
	info, err := os.Stat(c.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("cannot stat web token file; check web.token_file and container mount: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("web token must be a regular file, not a directory or device")
	}
	if info.Size() > 4096 {
		return nil, errors.New("web token file must be at most 4096 bytes")
	}
	if !c.AllowInsecureTokenPermissions && info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("web token file has group/other permissions; use mode 0600 or 0400, or explicitly set web.allow_insecure_token_permissions for ACL-managed storage")
	}
	token, err := os.ReadFile(c.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("cannot read web token file; check container user permissions: %w", err)
	}
	defer clear(token)
	if len(token) > 4096 {
		return nil, errors.New("web token file must be at most 4096 bytes")
	}
	value := strings.TrimSpace(string(token))
	if len(value) < 32 {
		return nil, errors.New("web token must have at least 32 characters; use web-token to generate one")
	}
	return &UI{
		service: service, ctx: ctx, config: c, token: sha256.Sum256([]byte(value)),
		sessions: make(map[[32]byte]session),
	}, nil
}

func randomToken() string {
	b := make([]byte, 32)
	// crypto/rand.Read only returns if the buffer is filled; fatal on failure.
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (u *UI) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", u.index)
	mux.HandleFunc("GET /style.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = w.Write([]byte(styles))
	})
	mux.HandleFunc("POST /login", u.logIn)
	for _, action := range []string{"unlock", "lock", "run", "logout"} {
		mux.HandleFunc("POST /"+action, u.action)
	}
	origin := http.NewCrossOriginProtection()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		origin.Handler(mux).ServeHTTP(w, r)
	})
}

func (u *UI) current(r *http.Request) (session, bool) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return session{}, false
	}
	hash := sha256.Sum256([]byte(cookie.Value))
	u.mu.Lock()
	defer u.mu.Unlock()
	now := time.Now()
	for key, s := range u.sessions {
		if !now.Before(s.Expires) {
			delete(u.sessions, key)
		}
	}
	s, ok := u.sessions[hash]
	return s, ok
}

func (u *UI) index(w http.ResponseWriter, r *http.Request) {
	s, ok := u.current(r)
	if !ok {
		u.render(w, view{})
		return
	}
	u.render(w, view{Authenticated: true, CSRF: s.CSRF, Status: u.service.Status()})
}

func (u *UI) logIn(w http.ResponseWriter, r *http.Request) {
	u.mu.Lock()
	allowed := u.login.allow(time.Now())
	u.mu.Unlock()
	if !allowed {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "Too many attempts. Try again in a minute.", http.StatusTooManyRequests)
		return
	}
	if !parseForm(w, r) {
		return
	}
	hash := sha256.Sum256([]byte(r.PostForm.Get("token")))
	if subtle.ConstantTimeCompare(hash[:], u.token[:]) != 1 {
		w.WriteHeader(http.StatusUnauthorized)
		u.render(w, view{Message: "Anmeldung fehlgeschlagen."})
		return
	}
	cookie := randomToken()
	s := session{CSRF: randomToken(), Expires: time.Now().Add(sessionTTL)}
	u.mu.Lock()
	// Bounded state, also if multiple clients create sessions.
	if len(u.sessions) >= 32 {
		clear(u.sessions)
	}
	u.sessions[sha256.Sum256([]byte(cookie))] = s
	u.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: cookie, Path: "/", HttpOnly: true,
		Secure: u.config.SecureCookies, SameSite: http.SameSiteStrictMode,
		MaxAge: int(sessionTTL.Seconds()),
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func parseForm(w http.ResponseWriter, r *http.Request) bool {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		http.Error(w, "invalid content type", http.StatusUnsupportedMediaType)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, control.MaxRequest)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid or oversized form", http.StatusBadRequest)
		return false
	}
	return true
}

func (u *UI) action(w http.ResponseWriter, r *http.Request) {
	s, ok := u.current(r)
	if !ok {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	if !parseForm(w, r) {
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf")), []byte(s.CSRF)) != 1 {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	message := ""
	switch r.URL.Path {
	case "/unlock":
		u.mu.Lock()
		allowed := u.unlock.allow(time.Now())
		u.mu.Unlock()
		if !allowed {
			http.Error(w, "too many unlock attempts", http.StatusTooManyRequests)
			return
		}
		if err := u.service.Unlock(r.PostForm.Get("key")); err != nil {
			message = "Entsperren fehlgeschlagen: Schlüssel, Datei oder laufenden Job prüfen."
		} else {
			message = "Entsperrt. Geplante Jobs können jetzt laufen."
		}
		r.PostForm.Del("key")
	case "/lock":
		u.service.Lock()
		message = "Gesperrt. Ein laufender Job wird abgebrochen."
	case "/run":
		if err := u.service.Trigger(u.ctx); err != nil {
			message = "Job nicht gestartet: Dienst gesperrt oder bereits beschäftigt."
		} else {
			message = "Job gestartet. Seite zum Prüfen des Ergebnisses aktualisieren."
		}
	case "/logout":
		cookie, _ := r.Cookie(cookieName)
		u.mu.Lock()
		delete(u.sessions, sha256.Sum256([]byte(cookie.Value)))
		u.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/", MaxAge: -1, HttpOnly: true, Secure: u.config.SecureCookies, SameSite: http.SameSiteStrictMode})
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	u.render(w, view{Authenticated: true, CSRF: s.CSRF, Status: u.service.Status(), Message: message})
}

type view struct {
	Authenticated bool
	CSRF          string
	Status        job.Status
	Message       string
}

func (u *UI) render(w http.ResponseWriter, v view) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = page.Execute(w, v)
}

var page = template.Must(template.New("index").Parse(`<!doctype html>
<html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MailboxCleanUp</title><link rel="stylesheet" href="/style.css"></head>
<body><main><header><p class="eyebrow">LOKAL · VERSCHLÜSSELT · KONTROLLIERT</p><h1>MailboxCleanUp</h1>
<p>Archivieren und aufräumen. Du behältst den Schlüssel.</p></header>
{{if .Message}}<p role="status" class="notice">{{.Message}}</p>{{end}}
{{if not .Authenticated}}
<section><h2>Anmelden</h2><p>Der Web-Zugangstoken ist unabhängig vom Entschlüsselungsschlüssel.</p>
<form action="/login" method="post"><label>Zugangstoken<input type="password" name="token" required autocomplete="off" maxlength="4096"></label><button>Anmelden</button></form></section>
{{else}}
<section><h2>Dienststatus</h2><p class="badge">{{if .Status.Unlocked}}Entsperrt{{else}}Gesperrt{{end}}{{if .Status.Running}} · Job läuft{{end}}</p>
<p>{{if .Status.DryRun}}Dry-Run aktiv: keine Änderungen{{else}}Änderungsmodus aktiv: Regeln verändern das Postfach{{end}}<br>Zeitplan: {{if .Status.Schedule}}{{.Status.Schedule}} · {{.Status.Timezone}}{{else}}Nur externe / manuelle Aufrufe{{end}}</p>
<p>Nach einem Neustart muss der Dienst erneut entsperrt werden. Abmelden sperrt den Dienst nicht.</p><a href="/">Status aktualisieren</a></section>
{{if not .Status.Unlocked}}<section><h2>Postfachzugriff entsperren</h2>
<form action="/unlock" method="post"><input type="hidden" name="csrf" value="{{.CSRF}}">
<label>Privater age-Schlüssel<input type="password" name="key" required autocomplete="off" spellcheck="false" maxlength="1024"></label>
<p>Nur aus deinem Passwortmanager übernehmen. Wird nicht dauerhaft gespeichert.</p><button>Entsperren</button></form></section>{{end}}
<section><h2>Aktionen</h2><div class="actions">
<form action="/run" method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><button {{if not .Status.Unlocked}}disabled{{end}}>Job jetzt starten</button></form>
<form action="/lock" method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><button class="secondary">Dienst sperren</button></form>
<form action="/logout" method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><button class="secondary">Abmelden</button></form></div>
<p>Es gilt immer die konfigurierte Dry-Run-Einstellung. Diese Oberfläche kann sie nicht überschreiben.</p></section>
{{with .Status.Last}}<section><h2>Letzter Job</h2>
<p>{{if .Success}}Erfolgreich{{else}}Fehlgeschlagen{{end}} · {{if .DryRun}}Dry-Run: keine Änderungen{{else}}Änderungsmodus{{end}}</p>
<p>Start: {{.Started.Format "2006-01-02 15:04:05 MST"}}<br>Ende: {{.Finished.Format "2006-01-02 15:04:05 MST"}}</p>
{{if .Error}}<p>{{.Error}}</p>{{end}}
<div class="table"><table><thead><tr><th>Konto / Regel</th><th>Treffer</th><th>Bestätigte UIDs</th><th>Fehler</th></tr></thead><tbody>
{{range .Results}}<tr><td>{{.Account}} / {{.Rule}}</td><td>{{.Matched}}</td><td>{{.Changed}}</td><td>{{.Error}}</td></tr>{{end}}
</tbody></table></div></section>{{end}}
{{end}}<footer>Keine Mailinhalte. Keine externen Skripte. Keine Analyse-Dienste.</footer></main></body></html>`))

const styles = `:root{color-scheme:dark;font:16px/1.6 system-ui,sans-serif;background:#101923;color:#e8eff4}*{box-sizing:border-box}body{margin:0}main{max-width:900px;margin:auto;padding:48px 24px}header{margin-bottom:36px}h1{font-size:clamp(2rem,6vw,3.5rem);letter-spacing:-.05em;margin:8px 0}h2{font-size:1.2rem;margin-top:0}.eyebrow{letter-spacing:.14em;font-size:.7rem;color:#6edac2}p,footer{color:#b2c1cd}section{padding:24px;background:#182532;border:1px solid #2a3b4b;border-radius:16px;margin:16px 0}label{display:block}input{width:100%;padding:12px;margin:8px 0 16px;background:#101923;color:#fff;border:1px solid #526678;border-radius:8px;font:inherit}button{padding:11px 18px;border:0;border-radius:8px;background:#6edac2;color:#102323;font:inherit;font-weight:650;cursor:pointer}button.secondary{background:#304355;color:#e8eff4}button:disabled{opacity:.4;cursor:default}.actions{display:flex;flex-wrap:wrap;gap:12px}.badge,.notice{color:#8fe9d5}.notice{padding:16px;border:1px solid #6edac2;border-radius:8px}a{color:#8fe9d5}footer{font-size:.8rem;margin-top:32px}.table{overflow:auto}table{width:100%;border-collapse:collapse;text-align:left;font-size:.9rem}th,td{padding:10px;border-bottom:1px solid #304355}input:focus-visible,button:focus-visible,a:focus-visible{outline:2px solid #8fe9d5;outline-offset:3px}`
