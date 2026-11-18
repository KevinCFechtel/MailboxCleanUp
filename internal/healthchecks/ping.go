// Package healthchecks sends aggregate counts on success, never start/failure signals.
package healthchecks

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/KevinCFechtel/MailboxCleanUp/internal/job"
)

type Pinger struct {
	urlFile                     string
	allowInsecureURLPermissions bool
	client                      *http.Client
}

func New(urlFile string, timeout time.Duration, allowInsecureURLPermissions bool) *Pinger {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	transport.MaxResponseHeaderBytes = 8192
	transport.DisableKeepAlives = true
	return &Pinger{
		urlFile:                     urlFile,
		allowInsecureURLPermissions: allowInsecureURLPermissions,
		client: &http.Client{
			Timeout:   timeout,
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (p *Pinger) Ping(ctx context.Context, counts job.Counts) error {
	// Reload on every job to support URL rotation without a process restart.
	endpoint, err := readURL(p.urlFile, p.allowInsecureURLPermissions)
	if err != nil {
		return err
	}
	// This fixed DTO cannot include account names, rule names, mail data or errors.
	body, err := json.Marshal(counts)
	if err != nil {
		return errors.New("cannot encode healthchecks job counts")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return errors.New("cannot create healthchecks success request")
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := p.client.Do(request)
	if err != nil {
		// HTTP errors can contain the secret URL. Never return the raw error.
		return errors.New("healthchecks success request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("healthchecks success request was not acknowledged")
	}
	return nil
}

func readURL(file string, allowInsecurePermissions bool) (string, error) {
	f, err := os.Open(file)
	if err != nil {
		return "", errors.New("cannot open healthchecks URL file")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", errors.New("cannot stat healthchecks URL file")
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("healthchecks URL must be a regular file")
	}
	if info.Size() > 4096 {
		return "", errors.New("healthchecks URL file must be at most 4096 bytes")
	}
	if !allowInsecurePermissions && info.Mode().Perm()&0077 != 0 {
		return "", errors.New("healthchecks URL file has group/other permissions; use mode 0600 or 0400, or explicitly set healthchecks.allow_insecure_url_permissions for ACL-managed storage")
	}
	data, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(data) > 4096 {
		return "", errors.New("cannot read healthchecks URL file")
	}
	defer clear(data)
	value := strings.TrimSpace(string(data))
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", errors.New("healthchecks URL must be HTTPS without user info, query or fragment")
	}
	// Only a UUID success endpoint, not /start, /fail, /log or an exit-code URL.
	parts := strings.Split(path.Base(u.Path), "-")
	lengths := []int{8, 4, 4, 4, 12}
	if len(parts) != len(lengths) || strings.HasSuffix(u.Path, "/") {
		return "", errors.New("healthchecks URL must end with a check UUID")
	}
	for i, part := range parts {
		if len(part) != lengths[i] {
			return "", errors.New("healthchecks URL must end with a check UUID")
		}
		if _, err := hex.DecodeString(part); err != nil {
			return "", errors.New("healthchecks URL must end with a check UUID")
		}
	}
	return value, nil
}
