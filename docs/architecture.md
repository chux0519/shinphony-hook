# Architecture

Shinphony Hook is one Go executable with a long-running per-user service and a
short-lived CLI. Agent hooks call the CLI; the CLI writes to the local service;
the service queues and delivers notifications through the Shinphony push relay
to the paired phone.

## Process and IPC

- One binary, subcommands for `serve`, `event`, `status`, `doctor`, pairing,
  agent setup and service install/uninstall.
- The service listens only on a private local channel: a Unix domain socket
  under a short private directory, or a Windows named pipe restricted to the
  current user. It never opens a TCP port.
- The mobile app reaches the computer through the user's existing SSH access to
  install and pair. The Hook adds no new remote-management channel.
- Agent hooks are best effort: a failed hook must not block or terminate the
  agent's turn.

## Data and permissions

- New state lives in `~/.shinphony-agent` so it cannot collide with the older
  notifier files. Existing credentials are read from `~/.shinphony-notify` and
  are not rewritten.
- SQLite stores schema migrations, setup jobs, the notification outbox,
  delivery attempts and deduplication records. It stores event metadata, never
  terminal output, chat contents or arbitrary command arguments.
- The directory, database, WAL/SHM files and logs are private to the user
  (POSIX 0700/0600; Windows user ACL). SQLite is not treated as an encryption
  boundary.
- The database is local disk only; network shares are not supported. Writes use
  transactions, a schema version and a busy timeout, and recovery is tested
  across restarts.

## Delivery

- Events enter a bounded queue (2000 pending records). Delivery uses
  exponential backoff with jitter, at most eight attempts and a 24-hour expiry.
- Permanent failures such as 401/403 are not retried. Terminal records
  (`sent`, `failed`, `suppressed`) are kept for seven days for deduplication.
- A full queue rejects new events with a fixed `queue_full` status rather than
  silently dropping pending work.
- Delivery is at-least-once. A stable event id lets the relay deduplicate when
  it can.

## Private notifications (end-to-end encrypted)

- When a pairing carries the phone's X25519 key (`e2e` in the pairing input),
  the notification text is sealed on this machine: an ephemeral X25519 key, a
  key from HKDF-SHA256, then ChaCha20-Poly1305 with the pairing's `hostRef` as
  associated data. The relay receives the category, the opaque `hostRef` and a
  sealed envelope of at most 2800 bytes; it writes a generic alert and passes
  the envelope through, and the Notification Service Extension on the phone
  opens it. Nothing readable is stored by the relay beyond delivery.
- Live Activity updates never pass through that extension. The pairing's
  `liveActivityLines` choice decides between the state, time and `hostRef` only
  (off, the default) and today's plaintext title and terminal lines for the
  Live Activity alone (on). Notifications stay sealed either way.
- `testdata/e2e_vectors.json` holds fixed test keys and a nonce so the Go and
  Swift sides are checked against the same bytes. They are test-only.

## Services

- Linux: `systemd --user`; the installer checks the user manager and explains
  the `linger` requirement instead of silently changing system policy.
- macOS: a LaunchAgent for the current GUI user.
- Windows 11 native: a current-user scheduled task plus a bounded supervisor
  process and a Job Object, so uninstalling does not leave children behind.
- No platform asks for or stores a login password, and installers never request
  administrator rights implicitly. Unsupported environments are reported as
  unsupported rather than claimed to work.

## Release and trust

- `cmd/release` builds a TUF root, targets, snapshot and timestamp set and a
  signed manifest. The root key stays offline; CI holds only the targets,
  snapshot, timestamp and bootstrap keys.
- `deploy/root.json` is the pinned trust root; `deploy/bootstrap-public-key.txt`
  is the key the app embeds. `cmd/verifyrelease` checks a release directory or
  the published metadata against that root.
- `tool/bundle.sh` builds the six platform binaries with `-trimpath`,
  `-buildvcs=false` and stripped symbols. `tool/verify_reproducible.sh` rebuilds
  them and compares the hashes with the signed metadata.
- The site Worker (`site/`) serves the one-line installer at `/pair` and the
  release page at `/hook` from the same verified metadata. It refuses to serve
  hashes that do not verify.

## Extension boundary

New capabilities are versioned, opt-in and tested individually. The Hook does
not download or execute arbitrary plugins, does not execute remote shell
commands, and does not offer a general remote command API. Daemon upgrades must
not destroy the user's agent configuration, and the previous binary remains
available for rollback.