package mail

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/KevinCFechtel/MailboxCleanUp/internal/config"
	"github.com/KevinCFechtel/MailboxCleanUp/internal/secrets"
	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
)

func scriptedSession(t *testing.T, capabilities string) (*session, <-chan []string) {
	t.Helper()
	local, remote := net.Pipe()
	t.Cleanup(func() { local.Close(); remote.Close() })
	_ = local.SetDeadline(time.Now().Add(5 * time.Second))
	_ = remote.SetDeadline(time.Now().Add(5 * time.Second))
	done := make(chan []string, 1)
	go func() {
		var commands []string
		defer func() { done <- commands }()
		fmt.Fprintf(remote, "* PREAUTH [CAPABILITY IMAP4rev1 %s] ready\r\n", capabilities)
		scanner := bufio.NewScanner(remote)
		for scanner.Scan() {
			line := scanner.Text()
			parts := strings.SplitN(line, " ", 2)
			if len(parts) != 2 {
				return
			}
			tag, command := parts[0], parts[1]
			commands = append(commands, command)
			switch {
			case command == "CAPABILITY":
				fmt.Fprintf(remote, "* CAPABILITY IMAP4rev1 %s\r\n%s OK capability\r\n", capabilities, tag)
			case command == "LOGOUT":
				fmt.Fprintf(remote, "* BYE logout\r\n%s OK logout\r\n", tag)
				return
			case strings.HasPrefix(command, "EXAMINE ") || strings.HasPrefix(command, "SELECT "):
				fmt.Fprintf(remote, "* 2 EXISTS\r\n* FLAGS (\\Seen \\Deleted)\r\n%s OK [READ-ONLY] selected\r\n", tag)
			case strings.HasPrefix(command, "UID SEARCH "):
				fmt.Fprintf(remote, "* SEARCH 10 20\r\n%s OK search\r\n", tag)
			default:
				fmt.Fprintf(remote, "%s OK done\r\n", tag)
			}
		}
	}()
	c, err := client.New(local)
	if err != nil {
		t.Fatal(err)
	}
	c.Timeout = 5 * time.Second
	c.SetState(imap.SelectedState, &imap.MailboxStatus{Name: "INBOX"})
	return &session{client: c, conn: local, stop: func() bool { return true }}, done
}

func TestWireUsesUIDOperationsAndNeverGlobalExpungeOrClose(t *testing.T) {
	s, done := scriptedSession(t, "MOVE UIDPLUS")
	if ok, err := s.Supports("archive"); err != nil || !ok {
		t.Fatal("MOVE support check failed")
	}
	if ok, err := s.Supports("delete"); err != nil || !ok {
		t.Fatal("UIDPLUS support check failed")
	}
	if err := s.Select("INBOX", true); err != nil {
		t.Fatal(err)
	}
	uids, err := s.SearchBefore(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil || !slices.Equal(uids, []uint32{10, 20}) {
		t.Fatal("UID search failed")
	}
	if err := s.Archive([]uint32{10, 20}, "Archive"); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete([]uint32{10, 20}); err != nil {
		t.Fatal(err)
	}
	if err := s.Logout(); err != nil {
		t.Fatal(err)
	}
	commands := <-done
	var archive, store, expunge bool
	for _, command := range commands {
		switch {
		case strings.HasPrefix(command, "UID MOVE 10,20 "):
			archive = true
		case strings.HasPrefix(command, "UID STORE 10,20 "):
			store = true
		case command == "UID EXPUNGE 10,20":
			expunge = true
		}
		if command == "EXPUNGE" || command == "CLOSE" || strings.HasPrefix(command, "FETCH ") || strings.HasPrefix(command, "UID FETCH ") {
			t.Fatal("unsafe/unnecessary command:", command)
		}
	}
	if !archive || !store || !expunge {
		t.Fatalf("missing targeted operations: %v", commands)
	}
}

func TestConnectorVerifiesTLSAndRequiresUpgradeBeforeLogin(t *testing.T) {
	certServer := httptest.NewTLSServer(nil)
	testCert := certServer.TLS.Certificates[0]
	roots := x509.NewCertPool()
	roots.AddCert(certServer.Certificate())
	certServer.Close()
	for _, mode := range []string{"tls", "starttls", "untrusted", "reject-starttls"} {
		t.Run(mode, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan bool, 1)
			go func() {
				sawSecureLogin := false
				defer func() { done <- sawSecureLogin }()
				raw, err := listener.Accept()
				if err != nil {
					return
				}
				defer raw.Close()
				_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
				var wire net.Conn = raw
				secure := false
				if mode == "tls" || mode == "untrusted" {
					tlsConn := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{testCert}, MinVersion: tls.VersionTLS12})
					if tlsConn.Handshake() != nil {
						return
					}
					wire, secure = tlsConn, true
				}
				fmt.Fprint(wire, "* OK [CAPABILITY IMAP4rev1 STARTTLS] ready\r\n")
				reader := bufio.NewReader(wire)
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					parts := strings.SplitN(strings.TrimSpace(line), " ", 2)
					if len(parts) != 2 {
						return
					}
					tag, command := parts[0], parts[1]
					switch {
					case command == "STARTTLS":
						if mode == "reject-starttls" {
							fmt.Fprintf(wire, "%s NO TLS unavailable\r\n", tag)
							continue
						}
						fmt.Fprintf(wire, "%s OK begin TLS\r\n", tag)
						tlsConn := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{testCert}, MinVersion: tls.VersionTLS12})
						if tlsConn.Handshake() != nil {
							return
						}
						wire, secure = tlsConn, true
						reader = bufio.NewReader(wire)
					case command == "CAPABILITY":
						fmt.Fprintf(wire, "* CAPABILITY IMAP4rev1 MOVE UIDPLUS\r\n%s OK capabilities\r\n", tag)
					case strings.HasPrefix(command, "LOGIN "):
						sawSecureLogin = secure
						if !secure {
							return
						}
						fmt.Fprintf(wire, "%s OK [CAPABILITY IMAP4rev1 MOVE UIDPLUS] logged in\r\n", tag)
					case command == "LOGOUT":
						fmt.Fprintf(wire, "* BYE logout\r\n%s OK logout\r\n", tag)
						return
					}
				}
			}()
			tlsMode := mode
			if mode == "untrusted" {
				tlsMode = "tls"
			} else if mode == "reject-starttls" {
				tlsMode = "starttls"
			}
			connect := connector(time.Second, roots)
			if mode == "untrusted" {
				connect = Connector(time.Second)
			}
			s, err := connect(context.Background(), config.Account{Server: listener.Addr().String(), TLSMode: tlsMode}, secrets.Credential{Username: "fake-user", Password: "fake-password"})
			success := mode == "tls" || mode == "starttls"
			if success && err != nil {
				t.Fatal("secure connection failed:", err)
			}
			if !success && err == nil {
				t.Fatal("insecure connection accepted")
			}
			if s != nil {
				_ = s.Logout()
			}
			if sawSecureLogin := <-done; sawSecureLogin != success {
				t.Fatal("unexpected authentication before TLS")
			}
		})
	}
}

func TestCancellationInterruptsStalledGreeting(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		var b [1]byte
		_, _ = conn.Read(b[:])
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = Connector(time.Second)(ctx, config.Account{Server: listener.Addr().String(), TLSMode: "starttls"}, secrets.Credential{})
	if err == nil || time.Since(start) > 750*time.Millisecond {
		t.Fatal("job cancellation did not interrupt greeting")
	}
	<-done
}

func TestMissingCapabilitiesAndInvalidUIDsNeverMutate(t *testing.T) {
	s, done := scriptedSession(t, "")
	if s.Archive([]uint32{1}, "Archive") == nil || s.Delete([]uint32{1}) == nil {
		t.Fatal("missing capability accepted")
	}
	if s.Archive(nil, "Archive") == nil || s.Delete([]uint32{0}) == nil {
		t.Fatal("empty/wildcard set accepted")
	}
	_ = s.Logout()
	for _, command := range <-done {
		if !slices.Contains([]string{"CAPABILITY", "LOGOUT"}, command) {
			t.Fatal("capability fallback issued a mutation:", command)
		}
	}
}
