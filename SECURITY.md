# Security model

## Protected data and trust boundaries

- Persistently stored IMAP credentials are encrypted with age/X25519.
  The application does not persist the private key.
- The service starts locked after every process/container restart.
- After unlocking, the identity remains in process memory. Each job reads the
  encrypted file again and decrypts the credentials for that run.
- Locking discards the identity and signals cancellation of active jobs.
  Changes already made cannot be undone. The active operation may still
  complete on the server before the connection is closed.
- Go and the libraries used provide **no guarantee of complete memory erasure**.
  The garbage collector may leave copies behind. There is no promise that
  locking immediately erases every previously stored byte.
- `mlock` is not enforced. To prevent persistent storage on disk, swap must
  additionally be disabled or reliably encrypted, and hibernation, host/VM
  snapshots, and memory dumps must be considered. The program disables core
  dumps where possible; Compose additionally sets the core limit to zero.

Host/Docker administrators and processes with access to the Unix socket can
control the service. Root, a compromised kernel, or arbitrary code execution
in the unlocked process can access keys and passwords.
Encryption at rest does not prevent this.

## Web interface

- Disabled by default in code; enabled for loopback/SSH in the Compose example.
- Separate random access token; by default, the service rejects token files
  with POSIX group/other permissions.
- For ACL-managed NAS shares, only this permission check can be disabled with
  `web.allow_insecure_token_permissions: true` (default: `false`, startup
  warning when enabled). The operator must then secure access through host/NAS
  ACLs; the application does not check those ACLs. A regular file type,
  readability, maximum file size, and minimum token length remain required.
  The option affects neither socket nor monitoring permissions.
- Server-side sessions with an absolute lifetime of 15 minutes, an HttpOnly
  cookie, SameSite=Strict, and a configurable Secure attribute.
  No local browser storage of the key.
- Signing out invalidates the browser session, **not** the service's unlocked state.
- CSRF token plus Go origin/Fetch Metadata checks for state-changing requests.
- Global rate limits on sign-in and unlock attempts, bounded request size,
  header and read timeouts. The global limits can be exhausted by other users
  of the same private endpoint.
- CSP without scripts, no framing, no external content, no analytics,
  and no caching of sensitive responses.
- Not intended for public Internet exposure. Use VPN/SSH and HTTPS.
  HTTP is available only when explicitly allowed or bound to a numeric loopback address.
- The example uses HTTP and `secure_cookies: false` because of the SSH tunnel.
  Always set `secure_cookies: true` when using HTTPS.
- TLS may terminate at the proxy; the backend and proxy are then inside the
  trust boundary. Request bodies must not be logged there.
- Use password manager autofill only for the correct trusted URL.
  Browser extensions and the clipboard can expose secrets.

## IMAP and modifications

- TLS >= 1.2 with standard certificate/hostname verification. STARTTLS is
  mandatory when configured; there is no plaintext fallback or InsecureSkipVerify.
- No message content, subject lines, or senders are downloaded/logged.
- Raw IMAP server responses are not included in error reports.
- No global EXPUNGE/CLOSE operations. Archiving only with MOVE, deletion only
  with UIDPLUS. No automatic creation of destination folders.
- Dry-run is the default. A positive message limit applies per rule.
- Multiple commands/rules are not an atomic transaction. Network errors and
  concurrent mail clients can cause partial changes. Backups remain necessary.
- Configuration and credential changes on the host are privileged operations.
  An attacker with write access to the configuration can change servers and
  rules. Protect the configuration against unauthorized writes as well.

## Containers and operation

- Optional healthchecks.io monitoring sends an HTTPS POST only after successful
  jobs, containing aggregate match/archive/deletion counts and a dry-run flag.
  No raw errors, message content, folders, or account aliases are transmitted.
  The recipient also learns the IP address and time of success; the counts
  allow inferences about message volume.
- The ping URL is treated as a local secret and is not logged.
  HTTPS with certificate verification is mandatory; redirects and start/failure
  endpoints are rejected. By default, files with POSIX group/other permissions
  are rejected. For ACL-managed NAS shares, only this permission check can be
  disabled separately with `healthchecks.allow_insecure_url_permissions: true`
  (default: `false`, startup warning when monitoring is enabled).
  The operator must then secure access through host/NAS ACLs. Readability,
  a regular file type, the size limit, and URL validation remain required.
- Missing pings detect a locked/stalled service only according to the schedule
  and grace time configured in healthchecks.io, not immediately after a restart.

- No private key or real credentials in the image/build context.
- Non-root, read-only root filesystem, all capabilities dropped,
  no-new-privileges, bounded resources.
- No Docker socket in the application container.
- Only the private control socket resides in the RAM filesystem.
  The private age key is not stored as a file there either.
- The healthcheck reports a locked service as unhealthy and returns the unlock
  state through the private control socket. It does not test IMAP connectivity
  or job success. After maintenance/restarts, unlock and verify actual job results.
- The last result and browser sessions are held only in memory. Logs contain
  account/rule aliases, counts, and generic errors, not credentials.
  Protect these metadata and log retention appropriately as well.
- Plan backups of the encrypted file and separate backups of the private key;
  test recovery. If key or host compromise is suspected, first revoke IMAP/app
  passwords at the provider.

## Reporting vulnerabilities

Do not include real keys, credentials, or message content in public issues,
CI logs, or bug reports. Use private GitHub vulnerability reports if available
in the repository.
