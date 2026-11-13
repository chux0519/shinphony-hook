# Security policy

## Reporting a vulnerability

Please report security problems privately, not in a public issue.

- Use GitHub's **Report a vulnerability** / private security advisory on this
  repository once it is public.
- Before the repository is public, use the contact shown at
  <https://potafree.net/shinphony>.

Include the affected version or release sequence, the platform, what an
attacker could do, and a minimal reproduction if you have one. We aim to
acknowledge a report within a few days and to publish a fixed release before
disclosing details.

## What the Hook is allowed to do

The Hook is a notification client, not a remote administration tool.

- It runs as the logged-in user and installs no system-wide service.
- It never listens on a network port. Local clients use a private Unix socket
  (a current-user named pipe on Windows).
- It does not execute commands received from the phone, the relay or the
  network. The only remote operation it accepts is the pairing/install flow the
  user starts from the app.
- It does not store terminal output, chat messages, prompts or file contents in
  its database or logs. Events carry the agent, session and status metadata
  only.
- Its state directory is private to the user (POSIX 0700/0600, Windows user
  ACL). It refuses symlinks and unsafe ownership when installing.

## Release integrity

- Binaries are signed through TUF metadata. The app ships the pinned bootstrap
  public key; the Hook verifies the pinned root in `deploy/root.json` before it
  trusts a release.
- The root private key is kept offline and is never in this repository, the
  release workflow, or the relay.
- Release assets are hash-checked by the app and can be rebuilt and compared
  with `tool/verify_reproducible.sh`; see [docs/verify.md](docs/verify.md).
- The `/hook` page only ever shows hashes from verified metadata. When
  verification fails it shows no hashes.

## Push relay

The relay Worker is published under `worker/` (with the shared code it imports
from `server/`) so its behaviour can be audited. It receives notification
metadata and encrypted APNs payloads; APNs private keys and purchase proofs are
Worker secrets and are not in this repository.