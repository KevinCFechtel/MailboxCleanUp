package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const minimal = `{"credentials_file":"credentials.age","accounts":[{"name":"personal","server":"imap.example.com:993","tls_mode":"tls","rules":[{"name":"old","action":"delete","mailbox":"Trash","older_than_days":30}]}]}`

func load(t *testing.T, data string) (Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

func TestDefaultsAreSafe(t *testing.T) {
	c, err := load(t, minimal)
	if err != nil {
		t.Fatal(err)
	}
	if !c.DryRun || c.Web.Enabled || !c.Web.SecureCookies || c.MaxMessagesPerRule != 1000 {
		t.Fatalf("unsafe defaults: %+v", c)
	}
}

func TestShippedExamples(t *testing.T) {
	for _, name := range []string{"config.json", "config.cli-only.json"} {
		t.Run(name, func(t *testing.T) {
			c, err := Load(filepath.Join("..", "..", "examples", name))
			if err != nil {
				t.Fatal(err)
			}
			if !c.DryRun {
				t.Fatal("shipped examples must be dry-run")
			}
		})
	}
}

func TestRejectInvalidConfiguration(t *testing.T) {
	cases := map[string]string{
		"plaintext password": strings.Replace(minimal, `"credentials_file"`, `"pass":"secret","credentials_file"`, 1),
		"unknown field":      strings.Replace(minimal, `"tls_mode":"tls"`, `"tls_mode":"tls","typo":true`, 1),
		"plaintext imap":     strings.Replace(minimal, `"tls_mode":"tls"`, `"tls_mode":"plain"`, 1),
		"zero retention":     strings.Replace(minimal, `"older_than_days":30`, `"older_than_days":0`, 1),
		"negative limit":     strings.Replace(minimal, `"credentials_file"`, `"max_messages_per_rule":-1,"credentials_file"`, 1),
		"second document":    minimal + `{}`,
		"invalid cron":       strings.Replace(minimal, `"credentials_file"`, `"schedule":"* * * * * *","credentials_file"`, 1),
		"embedded timezone":  strings.Replace(minimal, `"credentials_file"`, `"schedule":"CRON_TZ=UTC * * * *","credentials_file"`, 1),
		"bad timeout":        strings.Replace(minimal, `"credentials_file"`, `"job_timeout":"0s","credentials_file"`, 1),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := load(t, data); err == nil {
				t.Fatal("configuration should have been rejected")
			}
		})
	}
}

func TestWebNetworkRequiresExplicitTransportChoice(t *testing.T) {
	c, err := load(t, minimal)
	if err != nil {
		t.Fatal(err)
	}
	c.Web = Web{Enabled: true, Listen: "0.0.0.0:8080", TokenFile: "token", SecureCookies: true}
	if err := c.Validate(); err == nil {
		t.Fatal("network HTTP must be opt-in")
	}
	c.Web.AllowInsecureHTTP = true
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.Web.AllowInsecureHTTP = false
	c.Web.TLSCertFile, c.Web.TLSKeyFile = "cert.pem", "key.pem"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestRuleValidation(t *testing.T) {
	c, _ := load(t, minimal)
	r := &c.Accounts[0].Rules[0]
	r.Action, r.Destination = "archive", r.Mailbox
	if c.Validate() == nil {
		t.Fatal("self move must be rejected")
	}
	r.Destination = "Archive"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.Accounts = append(c.Accounts, c.Accounts[0])
	if c.Validate() == nil {
		t.Fatal("duplicate account must be rejected")
	}
}
