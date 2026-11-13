---
name: shinphony-task-notify
description: Notify the user's paired Shinphony phone when an explicitly requested task has genuinely finished or needs the user's intervention. Use for work the user asks to be notified about; never treat an agent turn, tool result, background poll, or intermediate progress as task completion.
---

# Shinphony task notifications

The installed local daemon sends notifications to this user's paired phones.
Do not read pairing credentials, change notification settings, or reinstall the service.

At the start of a notification-enabled task, choose an opaque task ID and reuse
it for retries. Send `completed` only after the entire requested scope and its
required checks are done. Continuing work, a completed subtask, and a normal
assistant response do not qualify. For an actual blocker requiring user action,
send `attention` once; use `failed` only for a terminal task failure.

Read the installed executable path from `client.json`. For Codex, invoke it in
a separate shell tool call, after earlier calls have completed all task checks,
with exactly one standalone command and the arguments `task-intent TASK_ID STATUS`.
Quote the executable path for the shell; task ID and status must satisfy the
bounded ASCII rules below. Do not add pipes, redirects, environment assignments,
compound commands, wrappers, extra logging, or a thread argument. The trusted
Codex PostToolUse hook supplies the actual runtime thread and terminal context.

The command only prints a `pending` request. It does not send a notification.
Check the subsequent hook feedback for `accepted locally` for that task ID;
missing, disabled, untrusted or rejected hook feedback means delivery is
unverified. Do not claim it was sent or restart/approve hooks yourself. Local
acceptance is not proof of phone delivery. Ordinary Stop/turns are not completion.

For agents other than Codex, use the executable argument `task-event` and send
a JSON object on stdin, never through a shell-interpolated command. Fields:
`taskId` and `status`. Task ID: 1–64 ASCII letters/digits/underscore/hyphen.
Status: `completed`, `attention`, or `failed`. The older direct IPC path also
accepts optional `thread` for Codex integrations that explicitly support it;
never invent a thread ID or read transcripts to find one.

Do not include task text, screenshots, secrets, or conversation content in the
JSON. When the agent runs in an identifiable tmux pane, the notification
automatically includes up to six recent terminal lines; otherwise it is sent
without a preview. Notifications pass through Shinphony and Apple and may appear
on the lock screen; there is no separate content-preview switch.

On failure, report that notification delivery is unverified. Do not loop or
restart the daemon. A successful local command means accepted locally, not proof
the phone displayed it. Use the same task ID if the user requests a retry.
