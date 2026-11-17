// Package config loads the non-secret job configuration.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/robfig/cron/v3"
)

type Config struct {
	CredentialsFile    string    `json:"credentials_file"`
	Schedule           string    `json:"schedule"`
	Timezone           string    `json:"timezone"`
	DryRun             bool      `json:"dry_run"`
	MaxMessagesPerRule int       `json:"max_messages_per_rule"`
	JobTimeout         string    `json:"job_timeout"`
	CommandTimeout     string    `json:"command_timeout"`
	Socket             string    `json:"socket"`
	Web                Web       `json:"web"`
	Accounts           []Account `json:"accounts"`
}

type Web struct {
	Enabled           bool   `json:"enabled"`
	Listen            string `json:"listen"`
	TokenFile         string `json:"token_file"`
	TLSCertFile       string `json:"tls_cert_file"`
	TLSKeyFile        string `json:"tls_key_file"`
	AllowInsecureHTTP bool   `json:"allow_insecure_http"`
	SecureCookies     bool   `json:"secure_cookies"`
}

type Account struct {
	Name    string `json:"name"`
	Server  string `json:"server"`
	TLSMode string `json:"tls_mode"`
	Rules   []Rule `json:"rules"`
}

type Rule struct {
	Name          string `json:"name"`
	Action        string `json:"action"`
	Mailbox       string `json:"mailbox"`
	Destination   string `json:"destination,omitempty"`
	OlderThanDays int    `json:"older_than_days"`
}

func Load(path string) (Config, error) {
	c := Config{
		DryRun: true, MaxMessagesPerRule: 1000, Timezone: "UTC",
		Schedule: "0 3 * * *", JobTimeout: "10m", CommandTimeout: "30s",
		Socket: "/run/mailboxcleanup/control.sock",
		Web:    Web{Listen: "127.0.0.1:8080", SecureCookies: true},
	}
	f, err := os.Open(path)
	if err != nil {
		return c, fmt.Errorf("open configuration: %w", err)
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 1024*1024))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, fmt.Errorf("invalid configuration: %w", err)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return c, errors.New("configuration must contain exactly one JSON object")
	}
	return c, c.Validate()
}

func (c Config) Validate() error {
	if c.CredentialsFile == "" || c.Socket == "" {
		return errors.New("credentials_file and socket are required")
	}
	if c.MaxMessagesPerRule < 1 {
		return errors.New("max_messages_per_rule must be positive")
	}
	for _, value := range []string{c.JobTimeout, c.CommandTimeout} {
		duration, err := time.ParseDuration(value)
		if err != nil || duration <= 0 {
			return errors.New("job_timeout and command_timeout must be positive durations")
		}
	}
	if _, err := time.LoadLocation(c.Timezone); err != nil {
		return errors.New("unknown timezone")
	}
	if c.Schedule != "" {
		if _, err := ParseSchedule(c.Schedule); err != nil {
			return fmt.Errorf("invalid five-field schedule: %w", err)
		}
	}
	if len(c.Accounts) == 0 {
		return errors.New("at least one account is required")
	}
	names := map[string]bool{}
	for _, a := range c.Accounts {
		if !validName(a.Name) || names[a.Name] {
			return errors.New("account names must be unique non-empty identifiers (letters, digits, - or _)")
		}
		names[a.Name] = true
		host, port, err := net.SplitHostPort(a.Server)
		if err != nil || host == "" || port == "" {
			return fmt.Errorf("account %s: server must be host:port", a.Name)
		}
		if a.TLSMode != "tls" && a.TLSMode != "starttls" {
			return fmt.Errorf("account %s: tls_mode must be tls or starttls; plaintext is forbidden", a.Name)
		}
		if len(a.Rules) == 0 {
			return fmt.Errorf("account %s: at least one rule is required", a.Name)
		}
		ruleNames := map[string]bool{}
		for _, r := range a.Rules {
			if !validName(r.Name) || ruleNames[r.Name] {
				return fmt.Errorf("account %s: rule names must be unique identifiers", a.Name)
			}
			ruleNames[r.Name] = true
			if r.OlderThanDays < 1 || r.OlderThanDays > 36500 || strings.TrimSpace(r.Mailbox) == "" {
				return fmt.Errorf("rule %s: mailbox and older_than_days between 1 and 36500 are required", r.Name)
			}
			switch r.Action {
			case "archive":
				if strings.TrimSpace(r.Destination) == "" || strings.EqualFold(r.Mailbox, r.Destination) {
					return fmt.Errorf("rule %s: archive requires a different destination", r.Name)
				}
			case "delete":
				if r.Destination != "" {
					return fmt.Errorf("rule %s: delete must not specify a destination", r.Name)
				}
			default:
				return fmt.Errorf("rule %s: action must be archive or delete", r.Name)
			}
		}
	}
	if c.Web.Enabled {
		host, _, err := net.SplitHostPort(c.Web.Listen)
		if err != nil {
			return errors.New("web.listen must be host:port")
		}
		if c.Web.TokenFile == "" {
			return errors.New("web.token_file is required when web is enabled")
		}
		if (c.Web.TLSCertFile == "") != (c.Web.TLSKeyFile == "") {
			return errors.New("web TLS requires both certificate and key")
		}
		ip := net.ParseIP(host)
		loopback := ip != nil && ip.IsLoopback()
		if c.Web.TLSCertFile == "" && !loopback && !c.Web.AllowInsecureHTTP {
			return errors.New("non-loopback web listener requires TLS, or explicit allow_insecure_http behind a secure tunnel/proxy")
		}
	}
	return nil
}

func ParseSchedule(spec string) (cron.Schedule, error) {
	// Do not allow embedded TZ/CRON_TZ overrides or descriptors.
	if len(strings.Fields(spec)) != 5 {
		return nil, errors.New("expected five cron fields")
	}
	return cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow).Parse(spec)
}

func validName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}
