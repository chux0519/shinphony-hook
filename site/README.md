# `shinphony.app` site Worker

The Worker behind `https://shinphony.app`, the address a person pastes into a
terminal:

```sh
curl -fsSL https://shinphony.app/pair | sh
```

It is a separate Worker (`site/`, its own `wrangler.jsonc`) from the push relay
in `worker/`. It holds no secrets, no Durable Objects and no KV: every request is
answered from code plus the signed release metadata on
`downloads.potafree.net`.

| Route | Answer |
| --- | --- |
| `GET /pair` | `text/plain; charset=utf-8`, `cache-control: no-store`: the filled bootstrap script |
| `GET /hook` | `text/html; charset=utf-8`: release sequence, date, signed hashes and verify commands |
| `GET /` | `302` to `https://potafree.net/shinphony` |
| anything else | `404` |

## Where the hashes come from

`GET /pair` never invents a hash. For each request (cached in the isolate for at
most five minutes) the Worker fetches `timestamp.json`, `snapshot.json` and
`targets.json` from `https://downloads.potafree.net/agent/stable/metadata/` and
verifies them against the pinned root that the Hook already ships:

- the root is `deploy/root.json` in this repository (`src/pinned-root.mjs`
  imports those exact bytes; the tests assert they still match);
- every role must carry a threshold of signatures from the keys the root lists,
  over the TUF canonical JSON of its `signed` object;
- every role must be unexpired, and the snapshot/targets versions and
  sha256/length declared by the parent role must match the bytes fetched;
- each `agent/<platform>` target must carry a 64-hex sha256, a length within the
  64 MiB limit and the matching `custom` platform/apiVersion.

On any failure the Worker answers **200** with a script that only prints
"temporarily unavailable" and the header `x-shinphony-setup: unavailable` for
monitoring. (A 4xx/5xx status would be wrong for the advertised command:
`curl -fsSL` throws the body away, so the user would see only curl's error line.)
The refusal script never runs anything and never contains a hash. That is the U1
acceptance behaviour: tampered, expired or unavailable metadata never produces a
"verified" script.

No new keys are involved: this is the reader side of the same TUF repository the
Hook's updater uses. Rotating the root means redeploying this Worker with the
new `deploy/root.json`.

## The `/hook` page

`GET /hook` is plain HTML with no JavaScript, built from the same verified
metadata (all six platforms). It shows the current sequence and release date
(derived from the `YYYYMMDDNN` sequence), the signed sha256 per platform, and the
commands to check an installed binary and to rebuild the release. On a metadata
failure it answers `503` with a short "temporarily unavailable" page and shows no
hashes.

The source link is optional: set the Worker variable `SOURCE_URL` to the public
repository URL (https only). While it is unset or not https, the page hides the
link. `deploy/root.json` is still the pinned root; no new secret is involved.

## The script

`pair.sh.tmpl` is the reviewed template. The Worker replaces
`@@DARWIN_ARM64@@`, `@@DARWIN_AMD64@@`, `@@LINUX_ARM64@@`, `@@LINUX_AMD64@@`,
`@@SEQUENCE@@` and `@@DOWNLOAD_BASE@@` and refuses to serve a script with any
`@@...@@` left. The install logic mirrors `install.sh` in the repository root:

- POSIX `sh`, macOS and Linux, arm64 and x86_64 only (Windows gets a pointer to
  the phone-pinned command);
- refuses root, refuses a linked or non-private `~/.shinphony-agent`, never
  overwrites an existing path (hard-link install, mode 700);
- reuses an already installed helper with the expected hash instead of
  downloading again;
- verifies the download's sha256 before installing (with `--progress-bar`, since
  a 16 MB download is otherwise silent for minutes);
- needs a terminal (`/dev/tty`) and otherwise exits 2 with "Run this in a
  terminal";
- finally `exec "$binary" pair </dev/tty >/dev/tty` so the QR prompt and its
  scanner instruction appear on the terminal, not in curl's pipe.

The whole script stays under 8 KiB (about 4.7 KiB filled).

## Local development and tests

```sh
cd site
npm install                   # wrangler (dev dependency only); commits a lockfile
npm test                      # node --test: metadata, script filling, /hook, routes
sh test/pair_test.sh          # the bootstrap script with fake curl/uname/id
npx wrangler dev --local      # http://127.0.0.1:8787/pair
curl -fsS http://127.0.0.1:8787/pair | sh   # real install, your own user only
```

Overrides exist for local runs only:

```sh
npx wrangler dev --local \
  --var METADATA_BASE:https://downloads.potafree.net/agent/stable/metadata \
  --var DOWNLOAD_BASE:http://127.0.0.1:8788 \
  --var SOURCE_URL:https://github.com/example/shinphony-hook
```

`DOWNLOAD_BASE` accepts `https://…` or a loopback `http://127.0.0.1:<port>`
(nothing else); the served script picks `--proto` accordingly. The refusal
script can be produced by pointing `METADATA_BASE` at a path that does not exist
(`-D -` shows `x-shinphony-setup: unavailable`).

The Worker tests use a captured, real metadata set in
`test/fixtures/release-2026111201/` (public signed data) so verification is
tested against go-tuf's actual output, not only against fixtures the tests sign
themselves.

## Deploy (needs the user's yes)

```sh
cd site && npm install && npx wrangler deploy
# optional, once the public repository exists:
npx wrangler deploy --var SOURCE_URL:https://github.com/<owner>/shinphony-hook
```

The `routes` entry claims the `shinphony.app` custom domain; `workers_dev` is
`false` so the Worker is not also reachable at
`shinphony-site.<account>.workers.dev`, which the zone rate limit would not
cover. Astra should also add the zone rate-limit rule for this hostname (same
style as `notify.potafree.net`: 30 requests per 10 s per IP). Neither step is
done by this change.