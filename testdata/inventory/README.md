# Inventory v1 fixtures

`shinphony-hook inventory` prints one JSON document: every conversation on this
host merged with the state the agent tracker knows. The App consumes these files
as the contract and renders its Agents lens from them; the Hook's tests compare
its own output against them byte for byte, so a change here is a contract change.

## Files

| File | What it pins |
|---|---|
| `all-states.json` | one row for each state: `question`, `approval`, `working`, `done`, `failed`, `idle`, `unknown` — hook- and mux-sourced, plus one hc helper with a parent |
| `each-mux.json` | every mux the Hook emits: `hc`, `tmux`, `zellij`, `shell` (screen sessions are plain shell rows) |
| `hc-helpers.json` | helper → parent links by hc address, and an orphan whose parent is gone |
| `errors.json` | a source that failed: codes only, no raw stderr, and no rows |
| `truncation.json` | the 200-conversation limit: quiet rows go first, `since` oldest first, and a dropped parent leaves no dangling link |

Regenerate after an intentional change (and say so in the iteration notes):

```sh
go test -run Inventory -update-inventory .
```

## Document

```json
{ "schema": 1, "generatedAt": 1763250000, "host": "",
  "conversations": [ … ], "errors": [] }
```

- `host` is empty: the App knows which host it asked over SSH.
- `errors` is always present; codes are `hc_unavailable`, `tmux_unavailable`,
  `zellij_unavailable`, `screen_unavailable`. A multiplexer with nothing to list
  (no tmux server, `No Sockets found`, no zellij session) is not an error.
- At most 200 conversations. Truncation order: `unknown` first, then `idle`,
  `done`, `working`, `failed`, `question`, `approval`; inside a group the oldest
  `since` goes first.

## Row

- `id` is `c_` + the first 16 hex of `sha256(mux \0 session \0 window id)`. It is
  stable across daemon restarts, renames and state changes; tmux uses
  `session_id`/`window_id`, hc the core session and terminal address, zellij and
  screen the session name.
- `mux` is `hc`, `tmux`, `zellij` or `shell` (a screen session). `rex` is in the
  vocabulary but is not collected: the Hook has no machine-readable rex listing.
- `group.kind` is `hcSpace` (with the hc space name), `tmuxSession` (with the
  session name) or `other` with an empty name.
- `state` + `stateSource`:
  - `hook` is exact: the agent's own hook event. This is the only source that may
    say `question` or `approval`, and the only one that knows `done`/`failed`.
  - `mux` is coarse: `working` when the multiplexer's status or activity is
    recent (60 s), otherwise `idle`.
  - `none`: the multiplexer proved the conversation exists and nothing more.
  - `done` decays to `idle` after 24 h; `failed` stays until a new turn starts.
- `since` is the last state change: the hook event, the hc status change (or the
  terminal's creation), the tmux window activity, or the observation time for a
  plain row.
- `message` is at most 120 characters and only ever the text of a question or an
  approval request; it is empty otherwise.
- `parent` is the `id` of the conversation a helper belongs to, and is present
  only when that conversation is in the same document. Helpers fold under it.
- `route` is a `taskContext`, the same shape a notification tap carries:
  `multiplexer`, `session` and `window` name the conversation (`window` is the hc
  terminal address), `agent`/`title` describe it, and `parent`/`parentTitle`/
  `space` place an hc helper. `route` and `binary` are empty: these rows name a
  conversation, not one agent event, so the App opens the terminal itself and
  never replays an event through `resolve-event`.
- `title`, `message`, `group.name` and `directory` are cleaned: no control or
  bidi characters, no newlines.