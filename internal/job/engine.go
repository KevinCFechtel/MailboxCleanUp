package job

import (
	"context"
	"errors"
	"time"

	"github.com/KevinCFechtel/MailboxCleanUp/internal/config"
	"github.com/KevinCFechtel/MailboxCleanUp/internal/secrets"
)

type Session interface {
	Supports(action string) (bool, error)
	Select(mailbox string, readOnly bool) error
	SearchBefore(before time.Time) ([]uint32, error)
	Archive(uids []uint32, destination string) error
	Delete(uids []uint32) error
	Logout() error
}

type Connect func(context.Context, config.Account, secrets.Credential) (Session, error)

// Counts contains only aggregate rule hits and UIDs in confirmed commands.
// It is not a count of distinct messages across rules.
type Counts struct {
	Matched  int  `json:"matched"`
	Archived int  `json:"archived"`
	Deleted  int  `json:"deleted"`
	DryRun   bool `json:"dry_run"`
}

type RuleResult struct {
	Account string `json:"account"`
	Rule    string `json:"rule"`
	Matched int    `json:"matched"`
	Changed int    `json:"changed"`
	Error   string `json:"error,omitempty"`
}

type Report struct {
	Started  time.Time    `json:"started"`
	Finished time.Time    `json:"finished"`
	DryRun   bool         `json:"dry_run"`
	Success  bool         `json:"success"`
	Results  []RuleResult `json:"results"`
	Error    string       `json:"error,omitempty"`
}

type Engine struct {
	Config        config.Config
	Store         *secrets.Store
	Connect       Connect
	Now           func() time.Time
	NotifySuccess func(context.Context, Counts) error
}

func (e *Engine) Run(ctx context.Context) Report {
	now := time.Now
	if e.Now != nil {
		now = e.Now
	}
	report := Report{Started: now(), DryRun: e.Config.DryRun, Success: true}
	counts := Counts{DryRun: e.Config.DryRun}
	deferFunc := func() Report {
		report.Finished = now()
		return report
	}
	credentials, err := e.Store.Read()
	if err != nil {
		report.Success = false
		report.Error = "credentials unavailable; unlock again or check encrypted file"
		return deferFunc()
	}
	// Drop references as soon as this run ends. Go cannot guarantee memory erasure.
	defer clear(credentials.Accounts)
	location, _ := time.LoadLocation(e.Config.Timezone)
	for _, account := range e.Config.Accounts {
		if ctx.Err() != nil {
			report.Success = false
			report.Error = "job cancelled or timed out"
			break
		}
		session, err := e.Connect(ctx, account, credentials.Accounts[account.Name])
		if err != nil {
			report.Success = false
			report.Results = append(report.Results, RuleResult{Account: account.Name, Error: "connection or authentication failed"})
			continue
		}
		for _, rule := range account.Rules {
			result := apply(ctx, session, e.Config, account.Name, rule, report.Started.In(location))
			report.Results = append(report.Results, result)
			counts.Matched += result.Matched
			if rule.Action == "archive" {
				counts.Archived += result.Changed
			} else if rule.Action == "delete" {
				counts.Deleted += result.Changed
			}
			if result.Error != "" {
				report.Success = false
				// Stop this account: dependent rules must not run after a failure.
				break
			}
		}
		if err := session.Logout(); err != nil {
			report.Success = false
			report.Results = append(report.Results, RuleResult{Account: account.Name, Error: "logout failed"})
		}
	}
	if ctx.Err() != nil {
		report.Success = false
		report.Error = "job cancelled or timed out"
	}
	if report.Success && e.Config.Healthchecks.Enabled && (!e.Config.DryRun || e.Config.Healthchecks.PingOnDryRun) {
		if e.NotifySuccess == nil || e.NotifySuccess(ctx, counts) != nil {
			report.Success = false
			report.Error = "mailbox processing succeeded, but healthchecks success ping failed"
		}
	}
	return deferFunc()
}

func apply(ctx context.Context, s Session, c config.Config, account string, r config.Rule, now time.Time) RuleResult {
	result := RuleResult{Account: account, Rule: r.Name}
	fail := func(message string) RuleResult {
		result.Error = message
		return result
	}
	if ctx.Err() != nil {
		return fail("job cancelled or timed out")
	}
	if !c.DryRun {
		ok, err := s.Supports(r.Action)
		if err != nil || !ok {
			return fail("required safe server capability missing (archive: MOVE; delete: UIDPLUS)")
		}
	}
	if err := s.Select(r.Mailbox, c.DryRun); err != nil {
		return fail("cannot select source mailbox")
	}
	// IMAP BEFORE compares INTERNALDATE at calendar-day precision, not elapsed hours.
	cutoff := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).AddDate(0, 0, -r.OlderThanDays)
	uids, err := s.SearchBefore(cutoff)
	if err != nil {
		return fail("message search failed")
	}
	result.Matched = len(uids)
	if len(uids) > c.MaxMessagesPerRule {
		return fail("message safety limit exceeded; no changes made by this rule")
	}
	if c.DryRun {
		return result
	}
	// Bound command size; never send an empty set (or an IMAP '*' wildcard).
	const batchSize = 200
	for start := 0; start < len(uids); start += batchSize {
		if ctx.Err() != nil {
			return fail("job cancelled or timed out; partial changes possible")
		}
		batch := uids[start:min(start+batchSize, len(uids))]
		if r.Action == "archive" {
			err = s.Archive(batch, r.Destination)
		} else {
			err = s.Delete(batch)
		}
		if err != nil {
			return fail("IMAP operation failed; partial changes possible; inspect mailbox before retrying")
		}
		result.Changed += len(batch)
	}
	return result
}

var ErrBusy = errors.New("a job is still running")
