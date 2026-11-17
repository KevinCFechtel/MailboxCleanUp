package job

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
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
func (f *fakeSession) Logout() error                      { f.loggedOut = true; return nil }
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
	_ = secrets.Encrypt(&b, secrets.Credentials{Accounts: map[string]secrets.Credential{"personal": {Username: "user", Password: "password"}}}, id.Recipient())
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
