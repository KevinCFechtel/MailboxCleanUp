// Package mail deliberately avoids COPY/STORE/EXPUNGE move fallbacks and CLOSE.
package mail

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/KevinCFechtel/MailboxCleanUp/internal/config"
	"github.com/KevinCFechtel/MailboxCleanUp/internal/job"
	"github.com/KevinCFechtel/MailboxCleanUp/internal/secrets"
	"github.com/emersion/go-imap"
	uidplus "github.com/emersion/go-imap-uidplus"
	"github.com/emersion/go-imap/client"
	"github.com/emersion/go-imap/commands"
)

type session struct {
	client *client.Client
	conn   net.Conn
	stop   func() bool
	once   sync.Once
}

func Connector(timeout time.Duration) job.Connect {
	return connector(timeout, nil)
}

// roots is nil in production (system CA store); tests use a private test CA.
func connector(timeout time.Duration, roots *x509.CertPool) job.Connect {
	return func(ctx context.Context, account config.Account, credential secrets.Credential) (job.Session, error) {
		host, _, _ := net.SplitHostPort(account.Server)
		tlsConfig := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, RootCAs: roots}
		conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", account.Server)
		if err != nil {
			return nil, errors.New("connect failed")
		}
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		fail := func() (job.Session, error) {
			stop()
			_ = conn.Close()
			return nil, errors.New("secure IMAP connection or authentication failed")
		}
		// Covers greeting and TLS handshake before client.Timeout can be set.
		_ = conn.SetDeadline(time.Now().Add(timeout))
		var wire net.Conn = conn
		if account.TLSMode == "tls" {
			tlsConn := tls.Client(conn, tlsConfig)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				return fail()
			}
			wire = tlsConn
		}
		c, err := client.New(wire)
		if err != nil {
			return fail()
		}
		c.Timeout = timeout
		// Never log untrusted server responses, which can echo credentials.
		c.ErrorLog = log.New(io.Discard, "", 0)
		if account.TLSMode == "starttls" {
			if err := c.StartTLS(tlsConfig); err != nil {
				return fail()
			}
		}
		if err := c.Login(credential.Username, credential.Password); err != nil {
			return fail()
		}
		return &session{client: c, conn: conn, stop: stop}, nil
	}
}

func (s *session) Supports(action string) (bool, error) {
	if action == "archive" {
		return s.client.Support("MOVE")
	}
	return s.client.Support("UIDPLUS")
}

func (s *session) Select(mailbox string, readOnly bool) error {
	_, err := s.client.Select(mailbox, readOnly)
	return err
}

func (s *session) SearchBefore(before time.Time) ([]uint32, error) {
	criteria := imap.NewSearchCriteria()
	criteria.Before = before
	return s.client.UidSearch(criteria)
}

func uidSet(uids []uint32) (*imap.SeqSet, error) {
	if len(uids) == 0 {
		return nil, errors.New("empty UID set")
	}
	set := new(imap.SeqSet)
	for _, uid := range uids {
		if uid == 0 {
			return nil, errors.New("invalid UID zero")
		}
		set.AddNum(uid)
	}
	return set, nil
}

func (s *session) Archive(uids []uint32, destination string) error {
	set, err := uidSet(uids)
	if err != nil {
		return err
	}
	// Do not call Client.UidMove: that helper can fall back to global EXPUNGE.
	if ok, err := s.client.Support("MOVE"); err != nil || !ok {
		return errors.New("MOVE is required")
	}
	status, err := s.client.Execute(&commands.Uid{Cmd: &commands.Move{SeqSet: set, Mailbox: destination}}, nil)
	if err != nil {
		return err
	}
	return status.Err()
}

func (s *session) Delete(uids []uint32) error {
	set, err := uidSet(uids)
	if err != nil {
		return err
	}
	if ok, err := s.client.Support("UIDPLUS"); err != nil || !ok {
		return errors.New("UIDPLUS is required")
	}
	if err := s.client.UidStore(set, imap.FormatFlagsOp(imap.AddFlags, true), []interface{}{imap.DeletedFlag}, nil); err != nil {
		return err
	}
	return uidplus.NewClient(s.client).UidExpunge(set, nil)
}

func (s *session) Logout() (err error) {
	s.once.Do(func() {
		defer s.conn.Close()
		defer s.stop()
		// CLOSE would expunge other clients' deleted messages. Only LOGOUT is safe.
		err = s.client.Logout()
	})
	return err
}
