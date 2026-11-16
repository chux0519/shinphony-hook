# Inventory v1 fixtures

`shinphony-hook inventory` prints one JSON document: every conversation on this
host merged with the state the agent tracker knows. The App consumes these files
as the contract and renders its Agents lens from them; the Hook's tests compare
its own output against them byte for byte, so a change here is a contract change.

## Files

| File | What it pins |
|---|---|
| `all-states.json` | one row for each state: `question`, `approval`, `working`, `done`, `failed`, `idle`, `unknown` — hook- and mux-sourced, herdr's own `done`/`blocked`/`error`, a known agent herdr has no status for, plain shells, and a tmux pane only a hook makes an agent row; plus one hc helper with a parent |
| `each-mux.json` | every mux the Hook emits: `hc`, `tmux`, `zellij`, `shell` (screen sessions are plain shell rows), including a tmux shell whose output is one second old |
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
- `errors` is always present; codes are `daemon_unavailable`, `hc_unavailable`,
  `tmux_unavailable`, `zellij_unavailable`, `screen_unavailable`. A multiplexer
  with nothing to list (no tmux server, `No Sockets found`, no zellij session) is
  not an error. `daemon_unavailable` (first in the list) means the CLI could not
  ask the service, which is the only process holding the tracker's in-memory
  state: the rows are still valid, but **no** row can be `stateSource: hook`. It
  explains a whole document of coarse rows instead of leaving it to be guessed.
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
- `kind` is `agent` when the row carries an `agent` identity, `shell` when it is a
  plain terminal. It is exactly `agent != null`, spelled out so the App can group
  shells without inferring the rule (an App reading an older document treats a
  missing `kind` as `agent` when `agent` is set).
- `state` + `stateSource`:
  - `hook` is exact: the agent's own hook event. This is the only source that may
    say `approval`, and the only one that knows that an agent failed.
  - `mux` is coarse, and from herdr it is herdr's own word (one row, one word):

    | herdr `status.state` | `state` | note |
    |---|---|---|
    | `working` | `working` | |
    | `done` | `done` | decays to `idle` after 24 h (from the status change) |
    | `idle` | `idle` | |
    | `blocked` | `question` | the program asked something (`status.kind`: permission/question/auth); `message` is its `status.msg` |
    | `error` | `failed` | |
    | any other word | activity of the status change | a newer herdr; 60 s rule |

    tmux has no words of its own: a pane is `working` when its output is at most
    60 s old *and* its program is a known agent, otherwise `idle`.
  - `none`: the multiplexer proved the conversation exists and nothing more. A
    shell (no agent identity, no hook state) is `idle`/`none`: output proves that
    something ran, not that an agent is working, so a shell never says `working`.
    A known agent herdr never reported a status for is `unknown`/`none`.
  - `question` from `mux` is allowed on an hc row only (herdr's `blocked`), and
    the App may show it as "Needs you"; a tmux/shell row never claims that.
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