package job

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/KevinCFechtel/MailboxCleanUp/internal/secrets"
)

type Status struct {
	Unlocked bool    `json:"unlocked"`
	Running  bool    `json:"running"`
	DryRun   bool    `json:"dry_run"`
	Schedule string  `json:"schedule"`
	Timezone string  `json:"timezone"`
	Last     *Report `json:"last,omitempty"`
}

type Service struct {
	mu      sync.Mutex
	engine  *Engine
	log     *slog.Logger
	running bool
	cancel  context.CancelFunc
	done    chan struct{}
	last    *Report
}

func NewService(engine *Engine, log *slog.Logger) *Service {
	return &Service{engine: engine, log: log}
}

func (s *Service) Unlock(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	if s.running {
		err = ErrBusy
	} else {
		err = s.engine.Store.Unlock(key)
	}
	// Unlock errors are sanitized by the credential store; never log the key.
	if err != nil {
		s.log.Warn("unlock failed", "reason", err.Error())
		return err
	}
	s.log.Info("service unlocked")
	return nil
}

// Lock also interrupts active IMAP connections through the job context.
func (s *Service) Lock() {
	s.mu.Lock()
	s.engine.Store.Lock()
	if s.cancel != nil {
		s.cancel()
	}
	s.mu.Unlock()
}

func (s *Service) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Status{
		Unlocked: s.engine.Store.Unlocked(), Running: s.running, Last: s.last,
		DryRun: s.engine.Config.DryRun, Schedule: s.engine.Config.Schedule, Timezone: s.engine.Config.Timezone,
	}
}

// Trigger never queues overlapping jobs and uses the service lifetime, not an HTTP request.
func (s *Service) Trigger(parent context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return ErrBusy
	}
	if !s.engine.Store.Unlocked() {
		return secrets.ErrLocked
	}
	timeout, _ := time.ParseDuration(s.engine.Config.JobTimeout)
	ctx, cancel := context.WithTimeout(parent, timeout)
	s.cancel = cancel
	s.done = make(chan struct{})
	s.running = true
	go func() {
		defer cancel()
		report := s.engine.Run(ctx)
		s.mu.Lock()
		s.last = &report
		s.running = false
		s.cancel = nil
		close(s.done)
		s.mu.Unlock()
		s.log.Info("job finished", "success", report.Success, "dry_run", report.DryRun, "results", report.Results, "error", report.Error)
	}()
	return nil
}

func (s *Service) Wait() {
	s.mu.Lock()
	done := s.done
	s.mu.Unlock()
	if done != nil {
		<-done
	}
}
