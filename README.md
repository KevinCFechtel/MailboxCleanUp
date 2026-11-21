# MailboxCleanUp

A containerized Go service for scheduled IMAP archiving and deletion rules.
Combines [ImapDelete](https://github.com/KevinCFechtel/ImapDelete) and
[ImapArchive](https://github.com/KevinCFechtel/ImapArchive).

**No messages are modified by default.** Rules can make changes only after
manual unlocking **and** with `dry_run: false`.
Before the first live run, back up the mailbox and review matches in a dry-run.

## Features

- Multiple IMAP accounts with explicitly ordered rules.
- Archive to existing IMAP folders and permanently delete messages by age.
- Five-field cron with a time zone, bounded runtime, and no overlapping jobs.
- Credentials encrypted locally with **age/X25519**; no plaintext passwords in
  configuration, images, or environment variables.
- Unlock once after each **process/container restart**. Jobs then run without
  further interaction.
- Optional web interface: sign in, unlock, lock, start jobs, and view sanitized
  results. Can be disabled completely.
- CLI over a private Unix socket, plus an independent one-shot mode.
- Mandatory TLS with certificate verification; no message content downloads.
- Optional healthchecks.io success notification only after fully successful
  jobs; locked/skipped jobs do not send a ping.

## Architecture and keys

```text
Bitwarden / KeePassXC / another password manager
                    │ private age key, supplied manually once
                    ▼
           CLI or protected web interface
                    │
                    ▼
     Service holds identity only in process memory
                    │ decrypt for each job
                    ▼
 local credentials.age ──► IMAP rules over TLS
```

The application is deliberately **not tied to a password manager**.
It stores neither the password manager's master password nor a cloud access token.
Store only the private age key in your password manager, or alternatively in a
local KeePassXC database. Recovery is impossible without the key:
plan for a separate encrypted backup.

The web access token is a **separate** secret. It protects the interface but
cannot decrypt IMAP credentials on its own. It is stored locally in an
access-restricted file. However, a signed-in user can control an already
unlocked service.

## Quick start with Docker Compose

Prerequisites: Docker with Compose, SSH access to the host, and a password manager.
The examples assume a Linux NAS/server.
The image is built and checked exclusively through GitHub Actions.
A release tag such as `v1.0.0` must have been published successfully first.
For a private GHCR package, sign in beforehand with an account that has the
required permissions. A local Go installation is not required.

### 1. Prepare the configuration

```bash
mkdir -p config
cp examples/config.json config/config.json
docker compose pull
```

In `config/config.json`, configure at least the servers, account names,
source/destination folders, and retention periods. **Keep `dry_run: true` initially**.
Archive folders must already exist.

### 2. Generate encrypted credentials

```bash
docker run --rm -it --network none \
  --user "$(id -u):$(id -g)" \
  --mount "type=bind,src=$PWD/config,dst=/config" \
  ghcr.io/kevincfechtel/mailboxcleanup:latest credentials \
  --accounts personal \
  --output /config/credentials.age
```

For multiple accounts, use e.g. `--accounts personal,work`. Names must match the
configuration. Username and password are prompted for with input hidden.
Use a separate, revocable app password where possible.

The command writes **only encrypted credentials**. It then displays:

- the public recipient `age1…`: keep it for future password rotation;
- the private key `AGE-SECRET-KEY-…`: **save it in your password manager now**.

Do not store the private key in files alongside the configuration, in Compose,
in shell arguments, or in environment variables. Consider terminal recording
and clipboard exposure. The generation command may display the key once;
the running service never logs it.

### 3. Generate a web access token

```bash
docker run --rm -it --network none \
  --user "$(id -u):$(id -g)" \
  --mount "type=bind,src=$PWD/config,dst=/config" \
  ghcr.io/kevincfechtel/mailboxcleanup:latest web-token --output /config/web-token
```

Save this token in your password manager as well. It is **not** the age key.

The image runs as UID/GID `65532`. On a Linux host, mounted files must be
readable by this user. Example for the directory just created, which belongs
exclusively to this service:

```bash
sudo chown 65532:65532 config config/config.json config/credentials.age config/web-token
sudo chmod 0750 config
sudo chmod 0440 config/config.json
sudo chmod 0400 config/credentials.age config/web-token
```

Configure NAS ACLs/user mapping as needed. Do not simply make the web token
world-readable: by default, the service rejects token files with group/other
permissions. For ACL-managed NAS shares, see the following section.
Subsequent edits to these files require the appropriate host administrator
permissions.

#### Troubleshooting unlocking

Unlocking requires the private `AGE-SECRET-KEY-…`, not the public `age1…`
recipient or the web access token. The web interface displays a sanitized
failure reason; failed unlock attempts and successful unlocking are also
recorded in `docker compose logs mailboxcleanup`, without keys or credentials.

To diagnose an existing installation from the terminal:

```bash
docker exec -it mailboxcleanup mailboxcleanup unlock
```

The key is prompted for with input hidden. A missing credentials file indicates
a wrong `credentials_file` path or mount. Permission errors require checking
read access for container UID/GID `65532:65532`, including directory traversal
and NAS ACLs. A decryption failure can mean a mismatched key or an invalid file;
missing account credentials mean the configured account names do not match
the encrypted file, or its username/password fields are empty.
Do not regenerate or overwrite the encrypted credentials while diagnosing,
and never paste private keys or decrypted contents into logs or bug reports.

#### Synology/NAS: Manage web token permissions through ACLs

If the NAS reports POSIX group/other permissions despite restrictive ACLs,
the POSIX permission check can be disabled explicitly. Add this to the existing
`web` object in `config.json`:

```json
"allow_insecure_token_permissions": true
```

The default is `false`. When `true`, the service still checks that the token file
exists, is a readable regular file of at most 4096 bytes, and contains a token
of at least 32 characters. Only the POSIX group/other permission check is skipped;
a warning is logged at startup. The application does not evaluate NAS ACLs:
use NAS permissions to restrict access to the file and share to trusted users.
Anyone who can read the token can sign in to the web interface.

This is independent of the mount mode: to **create** the token file, the setup
container needs `/config:rw`; `/config:ro` is sufficient during normal operation.
A `:rw` mount is also allowed and does not change the file permission check.
The option neither creates a missing token file nor changes file permissions.
It affects neither the control socket nor the healthchecks.io URL file
(which has its own `healthchecks.allow_insecure_url_permissions` option).
Restart the service after changing the configuration.

### 4. Start the service and access the web interface securely

```bash
docker compose up -d
```

Compose publishes HTTP **only on the host's `127.0.0.1`**, not on its LAN/Internet
address. Connect from your own computer using an SSH tunnel:

```bash
ssh -N -L 18080:127.0.0.1:8080 user@nas
```

Open `http://localhost:18080` in your browser:

1. Sign in with the **web access token**.
2. Enter the **private age key** in the unlock form.
3. Select "Run job now" and review the dry-run results.

The HTTP example is intended only for this loopback/SSH setup.
The browser host and SSH endpoint are inside the trust boundary. A sign-in
session lasts 15 minutes; **signing out does not lock the service** and therefore
does not stop cron jobs.

After verification, set `dry_run` to `false` for actual changes and restart the
container. Unlock it again afterward. Configuration changes do not take effect
without a restart.

### HTTPS, VPN, and reverse proxies

For direct browser access over the network, **use HTTPS**, preferably with a
VPN as well; do not expose the interface to the public Internet.

- Direct TLS termination: specify `web.tls_cert_file` and `web.tls_key_file`,
  and set `allow_insecure_http: false` and `secure_cookies: true`.
- Reverse proxy: terminate TLS at a trusted proxy, set `secure_cookies: true`,
  and explicitly allow internal HTTP with `allow_insecure_http: true`. Do not
  expose the backend port publicly or to untrusted containers. Preserve the
  original `Host` so origin checks work.
- When using HTTPS, access the token/key form **only over HTTPS**.
- Do not use proxy/WAF configurations that log request bodies.
- A NAS HTTPS proxy on the same host can use the loopback port. A proxy in a
  different container cannot reach it through its own `127.0.0.1`;
  configure a dedicated, isolated Docker network for that setup.

The application does not automatically trust `X-Forwarded-*` headers. Cookie
behavior is configured explicitly. HTTP without secure cookies is appropriate
only in the protected SSH/loopback setup.

### Disable the web interface completely

```json
"web": {
  "enabled": false
}
```

In this case, **no TCP web server starts**, no web token is required, and no TLS
files are read. Optionally remove the `ports` section from Compose as well.
A complete example configuration is available in
[`examples/config.cli-only.json`](examples/config.cli-only.json).

## CLI

The minimal image has no shell; run the command directly:

```bash
docker exec -it mailboxcleanup mailboxcleanup unlock
docker exec mailboxcleanup mailboxcleanup status
docker exec mailboxcleanup mailboxcleanup healthcheck
docker exec mailboxcleanup mailboxcleanup run
docker exec mailboxcleanup mailboxcleanup lock
```

`unlock` reads the key from the terminal with input hidden. `--key-stdin`
optionally allows a direct pipe from a suitable local password manager tool,
without putting keys in arguments or environment variables. Never use
shell tracing (`set -x`) or `echo KEY` for this.

`run` starts asynchronously; `status` then returns the result and current status.
`lock` removes the identity and cancels an active job. Changes already confirmed
cannot be undone. Running operations are stopped by closing the IMAP connection;
there is no transaction or rollback.

All control commands support `--socket PATH`. The default is
`/run/mailboxcleanup/control.sock`, with file mode `0600`. Only processes with
access to this socket may control the service. Docker/host administrators are
considered trusted.

### Container healthcheck

Compose runs `mailboxcleanup healthcheck` every 30 seconds through the private
control socket, including when the web interface is disabled. It checks daemon
availability and whether mailbox access is unlocked (not the browser sign-in
session). The command times out after 4 seconds.

- Unlocked: `{"healthy":true,"unlocked":true}`, exit code `0`.
- Locked: `{"healthy":false,"unlocked":false}`, exit code `1`.
- Unreachable daemon or invalid status: exit code `1` with an error message.

After a restart or manual locking, the container becomes `unhealthy` until
mailbox access is unlocked. Docker marks it healthy at the next successful
check; an unhealthy status alone does not restart the container.
`status` remains an informational command and succeeds even while locked.
The healthcheck neither runs a job nor tests IMAP connectivity; review job
results or use the healthchecks.io integration to monitor successful processing.

### External cron and one-shot execution

An external host cron can call `docker exec mailboxcleanup mailboxcleanup run`.
The persistent, unlocked service continues to hold the key; cron does not need
a key. Disable the built-in schedule with `"schedule": ""`, or use only the
built-in cron. Concurrent requests are rejected, not queued.

An **independent** one-shot run is also possible:

```bash
docker compose run --rm --no-deps mailboxcleanup \
  once --config /config/config.json
```

This process needs to be unlocked separately. A fully independent, unattended
cron container cannot obtain the key from another process's memory.
For the intended workflow, use `serve` with the built-in cron or `run`.

## Monitoring with healthchecks.io

The optional integration reports **only fully successful jobs**, not container
availability. After a restart, the service remains locked and sends no pings
until it has been unlocked and a job has completed successfully.
The Docker healthcheck is independent and reports a locked service as unhealthy.

Configuration:

```json
"healthchecks": {
  "enabled": true,
  "url_file": "/config/healthchecks-url",
  "allow_insecure_url_permissions": false,
  "timeout": "5s",
  "ping_on_dry_run": false
}
```

1. Create a check on healthchecks.io or a self-hosted instance.
2. Save the **HTTPS success URL with the check UUID** as the only line in
   `config/healthchecks-url`, e.g.
   `https://hc-ping.com/00000000-0000-0000-0000-000000000001`.
   Do not use a `/start`, `/fail`, `/log`, exit-code, or slug URL.
3. Make the file readable by the container user `65532:65532` and set file mode
   `0400` or `0600`, or use the option below for NAS ACLs.
   The URL is a secret: anyone who knows it can fake success notifications.
   Do not put it in Git, logs, or shell arguments.
4. Configure the same cron schedule and time zone in healthchecks.io as for the
   job. For `0 3 * * *`, `Europe/Berlin`, and `job_timeout: "10m"`, for example,
   allow a grace time of 15 minutes. Enable notification channels there.
5. Restart the service, unlock it, and run a successful job.
   Verify that the check is actively monitored and the ping has arrived.
   A newly created check that has not yet started may wait for its first ping
   before becoming active.

**Synology/NAS:** If the file is protected by host/NAS ACLs but reports POSIX
group/other permissions, add this to the existing `healthchecks` object:

```json
"allow_insecure_url_permissions": true
```

The default is `false`. When `true`, only this file's POSIX permission check is
skipped. Readability, a regular file type, a maximum size of 4096 bytes, and
validation of the HTTPS success URL with its check UUID remain required.
The service does not evaluate NAS ACLs; restrict access to the file and share
to trusted users. When monitoring is enabled, the service logs a warning at
startup. The web token option does not replace this separate setting.
After changing the configuration, restart and unlock the service again.
Testing does not require another deletion run: use `dry_run: true` and
`healthchecks.ping_on_dry_run: true`, or wait for the next scheduled run.

**Detection speed depends on the interval:** For a daily job, failure to unlock
may not be noticed until the next day plus the grace time.
Short detection times require jobs to run correspondingly often.
The application deliberately sends no start, lock, failure, or heartbeat ping
that could conceal a missing successful job.

Behavior:

- An HTTPS POST with aggregate counts is sent only after successful processing
  of **all accounts and rules, including logout**. A successful run with no
  matches also counts.
- No ping on startup/unlock, for `status`, while locked, on overlapping jobs,
  timeouts, partial failures, exceeded message limits, or cancelled jobs.
- Dry-runs send **no** success ping by default. Set `ping_on_dry_run: true` for
  an intentionally monitored test setup.
- Manually triggered jobs and `once` can also send a success ping; for a check
  that should monitor scheduled runs only, consider a separate configuration
  without monitoring for manual one-shot runs.
- Requests contain only aggregate match/action counts and a dry-run flag;
  no account/rule names, folders, message content, keys, or error messages.
  HTTP redirects are not followed; there are no automatic retries.
- If the success notification fails, the run is reported as failed with a
  generic monitoring error. Mailbox changes remain in effect. On a timeout,
  the server may already have received the ping even if no acknowledgment
  arrived locally.
- The URL file is read again for each job. URL rotation does not require a
  restart; configuration changes do.

Tests for this integration run in the existing GitHub Actions test step using
simulated endpoints. CI does not ping a real healthchecks.io check.

### Job counts in the ping

The JSON body is visible in the ping details/logs on healthchecks.io, e.g.:

```json
{"matched":42,"archived":30,"deleted":12,"dry_run":false}
```

- `matched`: total matches across accounts and rules.
- `archived` / `deleted`: total UIDs in successfully confirmed archive/deletion
  commands, respectively.
- `dry_run`: identifies an optionally enabled dry-run ping. In this case,
  `archived` and `deleted` remain `0`, while `matched` shows the matches found.

These figures are **not counts of unique messages**: the same message can
match multiple rules, e.g. be archived first and deleted afterward.
Other mail clients can modify messages concurrently; the counts are not an
independent verification of the messages actually changed.
healthchecks.io exposes the ping payload; automatic time-series charts or a
dedicated statistics dashboard are not implemented.

## Configuration and rule semantics

[`examples/config.json`](examples/config.json) contains a complete example.
Unknown fields are rejected so typos do not go unnoticed.

| Field | Meaning |
|---|---|
| `credentials_file` | Local age file; read again for each job, maximum 1 MiB |
| `schedule` | Five-field cron, default `0 3 * * *`; `""` disables the built-in schedule |
| `timezone` | IANA time zone, default `UTC`; time zone data is embedded in the binary |
| `dry_run` | Default `true`; search and count only, open the source read-only |
| `max_messages_per_rule` | Positive limit, default 1000; if exceeded, this rule makes no changes |
| `job_timeout` / `command_timeout` | Positive Go durations, default `10m` / `30s` |
| `socket` | Private local control socket |
| `web.allow_insecure_token_permissions` | Default `false`; when `true`, skip only the web token file's POSIX permission check, e.g. for NAS ACLs; secure access on the host instead |
| `healthchecks.enabled` | Optional success monitoring, default `false` |
| `healthchecks.url_file` | Private file containing the HTTPS success URL and check UUID |
| `healthchecks.allow_insecure_url_permissions` | Default `false`; when `true`, skip only the URL file's POSIX permission check; secure access through host/NAS ACLs instead |
| `healthchecks.timeout` | Positive HTTP timeout up to 1 minute, default `5s`; the job timeout also applies |
| `healthchecks.ping_on_dry_run` | Also report dry-runs, default `false` |
| `accounts[].name` | Unique alias; the same name is used in encrypted credentials |
| `accounts[].server` | `host:port`, e.g. `imap.example.com:993` |
| `accounts[].tls_mode` | `tls` (implicit, usually 993) or mandatory `starttls` (usually 143) |
| `rules[].action` | `archive` or `delete` |
| `rules[].mailbox` | Exact IMAP source folder, including the provider-specific hierarchy separator |
| `rules[].destination` | Existing destination folder, only for `archive` |
| `rules[].older_than_days` | 1–36500 days; zero/negative values are rejected |

### What "older than" means

As in the predecessor projects, IMAP `BEFORE` is used: the **INTERNALDATE date**
is authoritative, not the `Date` header. The cutoff is today minus the retention
period, using calendar days in the configured time zone.
Messages dated on the cutoff day are retained. These are not rolling 24-hour
windows; IMAP compares date components here, not exact timestamps.

### Ordering, errors, and safety limits

- Accounts and rules execute in configuration order.
- Rules see the results of earlier rules. A message can therefore be archived
  and subsequently deleted by a later rule within the same job.
  Archiving does not change its original INTERNALDATE.
- On errors, processing stops for the affected account; other accounts are attempted.
- The message limit applies **per rule**, not per job. Completed rules are not
  rolled back if later errors occur.
- Changes are requested in UID batches of at most 200. Network errors may leave
  partial changes; check before running again.
- "Confirmed UIDs" counts UIDs in successfully confirmed commands, not an
  independently verified number of modified messages. Other mail clients can
  move or delete messages concurrently.
- Archiving requires **MOVE**. No COPY/EXPUNGE fallback.
- Deletion requires **UIDPLUS** and uses only `UID STORE` followed by
  `UID EXPUNGE` for the selected UIDs. No global `EXPUNGE`, no `CLOSE`.
- Dry-run can count without MOVE/UIDPLUS; check support before live operation.
- Jobs missed while locked are not caught up. Unlocking does not trigger an
  immediate run; the next cron time or "Run job now" applies.
- Consider cron time zones and daylight saving time: nonexistent times are
  skipped; UTC avoids local daylight saving edge cases.

## Rotate credentials

Create a new file using the saved public `age1…` recipient:

```bash
docker run --rm -it --network none \
  --user "$(id -u):$(id -g)" \
  --mount "type=bind,src=$PWD,dst=/work" \
  ghcr.io/kevincfechtel/mailboxcleanup:latest credentials \
  --accounts personal \
  --recipient age1YOUR_PUBLIC_RECIPIENT \
  --output /work/credentials.next.age
```

Re-enter all configured accounts. Install the new file atomically as
`config/credentials.age` with appropriate file permissions. Example:

```bash
sudo chown 65532:65532 credentials.next.age
sudo chmod 0400 credentials.next.age
sudo mv credentials.next.age config/credentials.age
```

The next run reads the new file. Compose mounts the entire directory for this
reason, rather than a single file inode. The private key stays the same;
if the key changes, lock the service and unlock it again.

Rotate the web token separately: create a new token file, replace it securely,
and restart the service. This invalidates all browser sessions and requires
IMAP access to be unlocked again.

## Migration and analysis of predecessor projects

Revisions analyzed:

- ImapDelete: `ffccead6cb32d3465ad12957f8c32a2377e7f367`
- ImapArchive: `2a729fe66252fe9df76d165c33be004e3ad5e345`
- CupNotifyer: CI/Dependabot template from `main` at the time of implementation.

Both predecessors consist of a Go entry point, JSON configuration, a nearly
identical IMAP handler, and an optional gocron service. ImapDelete removes
messages; ImapArchive moves them. This combined project preserves those core
features, not the unsafe implementation details.

| Finding in the old code | Implementation here |
|---|---|
| `user`/`pass` in JSON, optional unencrypted IMAP | Encrypted credential store, mandatory TLS |
| IMAP body/envelope downloaded just to select UIDs | UID search only, no message content or implicit marking as read |
| Rule and mutation errors ignored, matches counted as success | Explicit partial results, failure status, and processing stopped for the affected account |
| Global `EXPUNGE` and `CLOSE` on logout | Targeted UID EXPUNGE, LOGOUT only |
| Archiving uses sequence numbers and a library fallback | Native UID MOVE only |
| Indefinite waiting without signal handling/timeouts | Context cancellation, SIGTERM/SIGINT, and controlled shutdown |
| HTTP logger can dereference `nil` after network errors; response body left open | Structured, local, sanitized JSON logs instead of external log delivery |
| Container with unpinned base image and shell entrypoint | Versioned multi-stage build, static non-root image without a shell |

Old JSON files are **not loaded directly**, especially not plaintext passwords.
Manual mapping:

| Old | New |
|---|---|
| `server` + `port` | `accounts[].server` as `host:port` |
| `user` / `pass` | Interactive `credentials` command |
| `tls: true` | `tls_mode: "tls"` |
| `cronScheduleConfig` | `schedule` plus an explicit `timezone` |
| Delete: `durations[].mailbox` / `duration` | Rule with `action: "delete"`, `mailbox`, `older_than_days` |
| Archive: `sourceMailbox` / `destMailbox` / `duration` | Rule with `action: "archive"`, `mailbox`, `destination`, `older_than_days` |
| `logurl` | Removed; structured local logs, no automatic external delivery |
| `-runAsService` / `-configFile` | `serve --config …` or `once --config …`, respectively |

Old `duration: 0` rules are deliberately not supported: a positive retention
period is required. Handle old plaintext files and backups accordingly, and
rotate any passwords they contain where possible.

## Development and GitHub Actions

Tests, builds, and security checks run in GitHub Actions, not on the NAS or
through locally installed tools. The workflow uses the Go version from
`go.mod` and also validates the Compose configuration.

Tests use synthetic credentials and a local scripted IMAP transport, not a real
mailbox. Before deleting production messages, also verify behavior using a
dedicated test account at the actual provider.

The CI, modeled after CupNotifyer, provides:

- Formatting checks, race tests, `go vet`, build, and `govulncheck`;
- Dependency Review and CodeQL where the GitHub plan/repository settings allow;
- Container builds and Trivy scans for **amd64 and arm64**, including pull requests;
- Publishing only after successful checks for SemVer tags such as `v1.2.3`,
  under `ghcr.io/kevincfechtel/mailboxcleanup`;
- `latest` only for stable releases, plus version and SHA tags;
- Multi-architecture images with SBOM and build provenance;
- Weekly security runs and Dependabot for Go, Actions, and Docker;
- Actions and the Trivy image pinned to specific commits/digests.

For **private repositories**, CodeQL, Dependency Review, and SARIF uploads are
disabled by default because they require the relevant GitHub security features.
If these features are available and enabled, set the repository variable
`ENABLE_GITHUB_SECURITY=true`. Local Trivy/Go scans remain active without these
features. For GHCR publishing, `GITHUB_TOKEN` needs the `packages: write`
permission specified in the workflow, and the repository must be allowed to
publish the package.

No IMAP credentials have been stored in GitHub Secrets; CI never accesses a
real mailbox.

## Security boundaries

See [`SECURITY.md`](SECURITY.md). Encryption protects stored files and backups,
not a compromised unlocked host. Swap, memory dumps, host access, NAS backups,
browsers, and password managers are all part of the security model.
