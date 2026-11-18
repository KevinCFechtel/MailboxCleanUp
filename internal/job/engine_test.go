package job

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/KevinCFechtel/MailboxCleanUp/internal/config"
	"github.com/KevinCFechtel/MailboxCleanUp/internal/secrets"
)

type fakeSession struct {
	uids       []uint32
	capable    bool
	readOnly   bool
	before     time.Time
	operations []string
	calls      int
	failAt     int
	loggedOut  bool
	logoutErr  error
}

func (f *fakeSession) Supports(string) (bool, error) { return f.capable, nil }
func (f *fakeSession) Select(_ string, readOnly bool) error {
	f.readOnly = readOnly
	return nil
}
func (f *fakeSession) SearchBefore(before time.Time) ([]uint32, error) {
	f.before = before
	return f.uids, nil
}
func (f *fakeSession) Archive(_ []uint32, _ string) error { return f.op("archive") }
func (f *fakeSession) Delete(_ []uint32) error            { return f.op("delete") }
func (f *fakeSession) Logout() error                      { f.loggedOut = true; return f.logoutErr }
func (f *fakeSession) op(name string) error {
	f.calls++
	f.operations = append(f.operations, name)
	if f.calls == f.failAt {
		return errors.New("secret from untrusted IMAP server")
	}
	return nil
}

func fixture(t *testing.T) (*Engine, string) {
	t.Helper()
	id, _ := age.GenerateX25519Identity()
	var b bytes.Buffer
	_ = secrets.Encrypt(&b, secrets.Credentials{Accounts: map[string]secrets.Credential{
		"personal": {Username: "user", Password: "password"},
		"work":     {Username: "work-user", Password: "work-password"},
	}}, id.Recipient())
	path := filepath.Join(t.TempDir(), "credentials.age")
	if err := os.WriteFile(path, b.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	store := secrets.New(path, []string{"personal"})
	c := config.Config{DryRun: true, MaxMessagesPerRule: 1000, Timezone: "Europe/Berlin", JobTimeout: "1m",
		Accounts: []config.Account{{Name: "personal", Rules: []config.Rule{
			{Name: "archive", Action: "archive", Mailbox: "INBOX", Destination: "Archive", OlderThanDays: 30},
			{Name: "delete", Action: "delete", Mailbox: "Trash", OlderThanDays: 60},
		}}},
	}
	if err := store.Unlock(id.String()); err != nil {
		t.Fatal(err)
	}
	return &Engine{Config: c, Store: store}, id.String()
}

func TestDryRunNeverMutatesAndUsesCalendarDate(t *testing.T) {
	e, _ := fixture(t)
	f := &fakeSession{uids: []uint32{1, 2}}
	e.Connect = func(context.Context, config.Account, secrets.Credential) (Session, error) { return f, nil }
	e.Now = func() time.Time { return time.Date(2026, 4, 1, 10, 15, 0, 0, time.UTC) }
	report := e.Run(context.Background())
	if !report.Success || !f.readOnly || len(f.operations) != 0 || !f.loggedOut {
		t.Fatalf("unsafe dry run: %+v", report)
	}
	if f.before.Format("2006-01-02 15:04 MST") != "2026-01-31 00:00 CET" {
		t.Fatalf("incorrect calendar cutoff: %s", f.before)
	}
}

func TestSafetyLimitBeforeAnyMutation(t *testing.T) {
	e, _ := fixture(t)
	e.Config.DryRun, e.Config.MaxMessagesPerRule = false, 1
	f := &fakeSession{uids: []uint32{1, 2}, capable: true}
	e.Connect = func(context.Context, config.Account, secrets.Credential) (Session, error) { return f, nil }
	report := e.Run(context.Background())
	if report.Success || len(f.operations) != 0 || len(report.Results) != 1 || report.Results[0].Matched != 2 {
		t.Fatalf("limit did not stop account: %+v", report)
	}
}

func TestCapabilityFailureStopsAccount(t *testing.T) {
	e, _ := fixture(t)
	e.Config.DryRun = false
	f := &fakeSession{uids: []uint32{1}}
	e.Connect = func(context.Context, config.Account, secrets.Credential) (Session, error) { return f, nil }
	report := e.Run(context.Background())
	if report.Success || len(f.operations) != 0 || len(report.Results) != 1 {
		t.Fatal("unsafe fallback")
	}
}

func TestOrderAndEmptySearch(t *testing.T) {
	e, _ := fixture(t)
	e.Config.DryRun = false
	f := &fakeSession{uids: []uint32{1}, capable: true}
	e.Connect = func(context.Context, config.Account, secrets.Credential) (Session, error) { return f, nil }
	report := e.Run(context.Background())
	if !report.Success || !slices.Equal(f.operations, []string{"archive", "delete"}) {
		t.Fatalf("wrong rule ordering: %+v", report)
	}
	f.uids, f.operations = nil, nil
	report = e.Run(context.Background())
	if !report.Success || len(f.operations) != 0 {
		t.Fatal("empty search issued mutation")
	}
}

func TestPartialBatchFailureIsNotReportedAsSuccess(t *testing.T) {
	e, _ := fixture(t)
	e.Config.DryRun = false
	uids := make([]uint32, 250)
	for i := range uids {
		uids[i] = uint32(i + 1)
	}
	f := &fakeSession{uids: uids, capable: true, failAt: 2}
	e.Connect = func(context.Context, config.Account, secrets.Credential) (Session, error) { return f, nil }
	report := e.Run(context.Background())
	if report.Success || len(report.Results) != 1 || report.Results[0].Changed != 200 {
		t.Fatalf("partial failure hidden: %+v", report)
	}
	if bytes.Contains([]byte(report.Results[0].Error), []byte("secret")) {
		t.Fatal("server error leaked")
	}
}

func TestServiceSerializesAndLockCancelsRun(t *testing.T) {
	e, key := fixture(t)
	entered := make(chan struct{})
	e.Connect = func(ctx context.Context, _ config.Account, _ secrets.Credential) (Session, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	s := NewService(e, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := s.Trigger(context.Background()); err != nil {
		t.Fatal(err)
	}
	<-entered
	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			if !errors.Is(s.Trigger(context.Background()), ErrBusy) {
				t.Error("overlapping run accepted")
			}
			_ = s.Status()
		})
	}
	wg.Wait()
	if !errors.Is(s.Unlock(key), ErrBusy) {
		t.Fatal("key changed during run")
	}
	s.Lock()
	s.Wait()
	status := s.Status()
	if status.Unlocked || status.Running || status.Last == nil || status.Last.Success {
		t.Fatalf("lock/cancellation failed: %+v", status)
	}
	if !errors.Is(s.Trigger(context.Background()), secrets.ErrLocked) {
		t.Fatal("locked run accepted")
	}
}

func TestHealthchecksOnlyAfterCompleteSuccess(t *testing.T) {
	for _, scenario := range []string{
		"success", "no-matches", "disabled", "locked", "connection-failed",
		"operation-failed", "limit-exceeded", "logout-failed", "cancelled",
		"dry-run", "dry-run-opt-in", "notification-failed",
	} {
		t.Run(scenario, func(t *testing.T) {
			e, _ := fixture(t)
			e.Config.DryRun = false
			e.Config.Healthchecks.Enabled = true
			f := &fakeSession{uids: []uint32{1}, capable: true}
			e.Connect = func(context.Context, config.Account, secrets.Credential) (Session, error) { return f, nil }
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch scenario {
			case "no-matches":
				f.uids = nil
			case "disabled":
				e.Config.Healthchecks.Enabled = false
			case "locked":
				e.Store.Lock()
			case "connection-failed":
				e.Connect = func(context.Context, config.Account, secrets.Credential) (Session, error) {
					return nil, errors.New("connection failed")
				}
			case "operation-failed":
				f.failAt = 2 // A successful earlier rule must not trigger a ping.
			case "limit-exceeded":
				e.Config.MaxMessagesPerRule = 1
				f.uids = []uint32{1, 2}
			case "logout-failed":
				f.logoutErr = errors.New("logout failed")
			case "cancelled":
				cancel()
			case "dry-run":
				e.Config.DryRun = true
			case "dry-run-opt-in":
				e.Config.DryRun = true
				e.Config.Healthchecks.PingOnDryRun = true
			}
			calls := 0
			e.NotifySuccess = func(context.Context, Counts) error {
				calls++
				if !f.loggedOut {
					t.Error("ping happened before successful logout")
				}
				if scenario == "notification-failed" {
					return errors.New("untrusted error containing a secret URL")
				}
				return nil
			}
			report := e.Run(ctx)
			wantPing := scenario == "success" || scenario == "no-matches" || scenario == "dry-run-opt-in" || scenario == "notification-failed"
			if (calls == 1) != wantPing || calls > 1 {
				t.Fatalf("unexpected number of success pings: %d", calls)
			}
			wantSuccess := scenario == "success" || scenario == "no-matches" || scenario == "disabled" || scenario == "dry-run" || scenario == "dry-run-opt-in"
			if report.Success != wantSuccess || strings.Contains(report.Error, "secret URL") {
				t.Fatalf("unexpected report: %+v", report)
			}
		})
	}
}

func TestLockedServiceDoesNotPing(t *testing.T) {
	e, _ := fixture(t)
	e.Store.Lock()
	e.Config.Healthchecks.Enabled = true
	e.NotifySuccess = func(context.Context, Counts) error {
		t.Error("locked/skipped job sent a ping")
		return nil
	}
	s := NewService(e, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if !errors.Is(s.Trigger(context.Background()), secrets.ErrLocked) {
		t.Fatal("locked scheduled job accepted")
	}
	s.Wait()
}

func TestSuccessCountsAggregateAllRulesAndAccounts(t *testing.T) {
	for _, dryRun := range []bool{false, true} {
		t.Run(fmt.Sprint(dryRun), func(t *testing.T) {
			e, _ := fixture(t)
			e.Config.DryRun = dryRun
			e.Config.Healthchecks.Enabled = true
			e.Config.Healthchecks.PingOnDryRun = true
			// Same rules on a second account, with no dependency on real IMAP.
			work := e.Config.Accounts[0]
			work.Name = "work"
			e.Config.Accounts = append(e.Config.Accounts, work)
			e.Connect = func(context.Context, config.Account, secrets.Credential) (Session, error) {
				return &fakeSession{uids: []uint32{1, 2, 3}, capable: true}, nil
			}
			var received Counts
			calls := 0
			e.NotifySuccess = func(_ context.Context, counts Counts) error {
				calls++
				received = counts
				return nil
			}
			report := e.Run(context.Background())
			want := Counts{Matched: 12, Archived: 6, Deleted: 6, DryRun: dryRun}
			if dryRun {
				want.Archived, want.Deleted = 0, 0
			}
			if !report.Success || calls != 1 || received != want {
				t.Fatalf("unexpected aggregate counts: got %+v, want %+v", received, want)
			}
		})
	}
}
