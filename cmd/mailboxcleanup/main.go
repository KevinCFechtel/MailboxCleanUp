package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"filippo.io/age"
	"github.com/KevinCFechtel/MailboxCleanUp/internal/config"
	"github.com/KevinCFechtel/MailboxCleanUp/internal/control"
	"github.com/KevinCFechtel/MailboxCleanUp/internal/job"
	"github.com/KevinCFechtel/MailboxCleanUp/internal/mail"
	"github.com/KevinCFechtel/MailboxCleanUp/internal/secrets"
	"github.com/KevinCFechtel/MailboxCleanUp/internal/web"
	"github.com/robfig/cron/v3"
	"golang.org/x/term"
	_ "time/tzdata"
)

func main() {
	syscall.Umask(0077)
	// Do not intentionally dump the unlocked process memory to disk.
	_ = syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0})
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: mailboxcleanup {serve|once|unlock|lock|status|run|credentials|web-token} [options]")
	}
	switch args[0] {
	case "serve", "once":
		fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
		path := fs.String("config", "config.json", "non-secret configuration")
		stdin := fs.Bool("key-stdin", false, "once: read private key from stdin instead of terminal")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 || (args[0] == "serve" && *stdin) {
			return errors.New("unexpected arguments")
		}
		c, err := config.Load(*path)
		if err != nil {
			return err
		}
		engine := newEngine(c)
		if args[0] == "serve" {
			return serve(ctx, engine)
		}
		key, err := readKey(*stdin)
		if err != nil {
			return err
		}
		defer clear(key)
		if err := engine.Store.Unlock(string(key)); err != nil {
			return err
		}
		defer engine.Store.Lock()
		timeout, _ := time.ParseDuration(c.JobTimeout)
		runCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		report := engine.Run(runCtx)
		_ = json.NewEncoder(os.Stdout).Encode(report)
		if !report.Success {
			return errors.New("job failed")
		}
		return nil
	case "unlock", "lock", "status", "run":
		return controlCommand(ctx, args)
	case "credentials":
		return createCredentials(args[1:])
	case "web-token":
		return createWebToken(args[1:])
	case "help", "-h", "--help":
		fmt.Println(`MailboxCleanUp
  serve --config config.json          Locked daemon with cron and optional web UI
  unlock [--key-stdin]                 Unlock the daemon; otherwise hidden terminal input
  lock                                Lock daemon and cancel active job
  status                              Show sanitized daemon status as JSON
  run                                 Trigger a job in the unlocked daemon
  once --config config.json           Standalone job; prompts for key
  credentials --accounts personal     Create encrypted credentials and an age key
  credentials --accounts personal --recipient age1... --output next.age
                                      Create rotated credentials for an existing key
  web-token --output web-token         Generate a separate web access token

Control commands accept --socket (default /run/mailboxcleanup/control.sock).
No private keys or passwords are accepted as command-line arguments.`)
		return nil
	default:
		return errors.New("unknown command; use --help")
	}
}

func newEngine(c config.Config) *job.Engine {
	names := make([]string, 0, len(c.Accounts))
	for _, a := range c.Accounts {
		names = append(names, a.Name)
	}
	timeout, _ := time.ParseDuration(c.CommandTimeout)
	return &job.Engine{Config: c, Store: secrets.New(c.CredentialsFile, names), Connect: mail.Connector(timeout)}
}

func server(handler http.Handler) *http.Server {
	return &http.Server{
		Handler: handler, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192,
	}
}

func serve(ctx context.Context, engine *job.Engine) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	service := job.NewService(engine, log)
	listener, err := control.Listen(engine.Config.Socket)
	if err != nil {
		return err
	}
	defer listener.Close()
	local := server(control.Handler(ctx, service))
	servers := []*http.Server{local}
	var webListener net.Listener
	var browser *http.Server
	if engine.Config.Web.Enabled {
		ui, err := web.New(ctx, engine.Config.Web, service)
		if err != nil {
			return err
		}
		webListener, err = net.Listen("tcp", engine.Config.Web.Listen)
		if err != nil {
			return errors.New("cannot bind web listener")
		}
		defer webListener.Close()
		browser = server(ui.Handler())
		servers = append(servers, browser)
		if engine.Config.Web.TLSCertFile == "" {
			log.Warn("web HTTP enabled: only use via loopback, SSH tunnel, VPN or HTTPS reverse proxy")
		}
	}
	errs := make(chan error, 2)
	go func() { errs <- local.Serve(listener) }()
	if browser != nil {
		go func() {
			c := engine.Config.Web
			if c.TLSCertFile != "" {
				errs <- browser.ServeTLS(webListener, c.TLSCertFile, c.TLSKeyFile)
			} else {
				errs <- browser.Serve(webListener)
			}
		}()
	}
	location, _ := time.LoadLocation(engine.Config.Timezone)
	scheduler := cron.New(cron.WithLocation(location))
	if engine.Config.Schedule != "" {
		_, err = scheduler.AddFunc(engine.Config.Schedule, func() {
			if err := service.Trigger(ctx); err != nil {
				log.Info("scheduled job skipped", "reason", err.Error())
			}
		})
		if err != nil {
			return errors.New("cannot configure scheduler")
		}
	}
	scheduler.Start()
	log.Info("service started locked", "web_enabled", engine.Config.Web.Enabled, "dry_run", engine.Config.DryRun)
	var serveErr error
	select {
	case <-ctx.Done():
	case err := <-errs:
		if !errors.Is(err, http.ErrServerClosed) {
			serveErr = errors.New("HTTP/control server failed")
		}
	}
	cancel()
	<-scheduler.Stop().Done()
	// Stop incoming unlock/run requests before dropping the identity.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	for _, s := range servers {
		if err := s.Shutdown(shutdownCtx); err != nil {
			_ = s.Close()
		}
	}
	service.Lock()
	service.Wait()
	log.Info("service stopped")
	return serveErr
}

func controlCommand(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	socket := fs.String("socket", "/run/mailboxcleanup/control.sock", "control socket")
	stdin := fs.Bool("key-stdin", false, "unlock: read key from stdin")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || (*stdin && args[0] != "unlock") {
		return errors.New("unexpected arguments")
	}
	method := http.MethodPost
	if args[0] == "status" {
		method = http.MethodGet
	}
	var body io.Reader
	if args[0] == "unlock" {
		key, err := readKey(*stdin)
		if err != nil {
			return err
		}
		defer clear(key)
		body = strings.NewReader(string(key))
	}
	request, err := http.NewRequestWithContext(ctx, method, "http://localhost/"+args[0], body)
	if err != nil {
		return errors.New("cannot create control request")
	}
	client := control.Client(*socket)
	defer client.CloseIdleConnections()
	response, err := client.Do(request)
	if err != nil {
		return errors.New("cannot reach daemon; check socket and container user")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 65536))
	if err != nil {
		return errors.New("cannot read daemon response")
	}
	if response.StatusCode >= 300 {
		return fmt.Errorf("daemon: %s", strings.TrimSpace(string(data)))
	}
	if len(data) > 0 {
		_, _ = os.Stdout.Write(data)
	} else {
		fmt.Println("OK")
	}
	return nil
}

func readKey(stdin bool) ([]byte, error) {
	if stdin {
		data, err := io.ReadAll(io.LimitReader(os.Stdin, control.MaxRequest+1))
		if err != nil || len(data) > control.MaxRequest {
			clear(data)
			return nil, errors.New("invalid key input")
		}
		return data, nil
	}
	return hidden("Privater age-Schlüssel: ")
}

func hidden(prompt string) ([]byte, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, errors.New("interactive terminal required (unlock/once alternatively accept --key-stdin)")
	}
	fmt.Fprint(os.Stderr, prompt)
	value, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, errors.New("cannot read hidden input")
	}
	return value, nil
}

func createCredentials(args []string) error {
	fs := flag.NewFlagSet("credentials", flag.ContinueOnError)
	accounts := fs.String("accounts", "", "comma-separated account names from configuration")
	output := fs.String("output", "credentials.age", "new encrypted file (never overwrite)")
	recipient := fs.String("recipient", "", "existing age public recipient, for rotation")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *accounts == "" || fs.NArg() != 0 {
		return errors.New("specify --accounts personal[,work]")
	}
	var id *age.X25519Identity
	var public *age.X25519Recipient
	var err error
	if *recipient == "" {
		id, err = age.GenerateX25519Identity()
		if err != nil {
			return errors.New("cannot generate age identity")
		}
		public = id.Recipient()
	} else {
		public, err = age.ParseX25519Recipient(*recipient)
		if err != nil {
			return errors.New("invalid public age recipient")
		}
	}
	c := secrets.Credentials{Accounts: make(map[string]secrets.Credential)}
	defer clear(c.Accounts)
	for _, value := range strings.Split(*accounts, ",") {
		name := strings.TrimSpace(value)
		if name == "" {
			return errors.New("empty account name")
		}
		if _, ok := c.Accounts[name]; ok {
			return errors.New("duplicate account name")
		}
		username, err := hidden(name + " Benutzername (verdeckt): ")
		if err != nil {
			return err
		}
		password, err := hidden(name + " IMAP-/App-Passwort (verdeckt): ")
		if err != nil {
			clear(username)
			return err
		}
		if len(username) == 0 || len(password) == 0 {
			clear(username)
			clear(password)
			return errors.New("username and password must not be empty")
		}
		c.Accounts[name] = secrets.Credential{Username: string(username), Password: string(password)}
		clear(username)
		clear(password)
	}
	if err := writePrivate(*output, func(w io.Writer) error { return secrets.Encrypt(w, c, public) }); err != nil {
		return err
	}
	fmt.Println("Verschlüsselte Zugangsdaten erstellt. Öffentlicher Empfänger:", public.String())
	if id != nil {
		fmt.Println("Jetzt im Passwortmanager speichern; ohne diesen privaten Schlüssel ist keine Wiederherstellung möglich:")
		fmt.Println(id.String())
	}
	return nil
}

func createWebToken(args []string) error {
	fs := flag.NewFlagSet("web-token", flag.ContinueOnError)
	output := fs.String("output", "web-token", "new private token file (never overwrite)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	value := make([]byte, 32)
	_, _ = rand.Read(value)
	token := base64.RawURLEncoding.EncodeToString(value)
	if err := writePrivate(*output, func(w io.Writer) error {
		_, err := fmt.Fprintln(w, token)
		return err
	}); err != nil {
		return err
	}
	fmt.Println("Web-Zugangstoken erstellt. Im Passwortmanager speichern:")
	fmt.Println(token)
	return nil
}

func writePrivate(path string, write func(io.Writer) error) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("cannot create output file (directory must exist; existing files are never overwritten)")
	}
	err = write(f)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(path) // Only the file just created by this invocation.
		return errors.New("cannot write output file")
	}
	return nil
}
