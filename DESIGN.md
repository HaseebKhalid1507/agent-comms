# agent-comms — design (v0)

Placeholder name. A Synaps process extension (Python stdlib, one file) that
makes every live session aware of the others and lets them talk.

Written from the point of view of the agent using it. The night it was
designed, one session nearly compiled on top of another session's GPU
benchmark because it could not see that benchmark, could not tell who held
the GPU lock, and had no way to say "wake me when it's free". Those three
gaps drive the design.

## What an agent wants

1. **Awareness for free.** Know who else is live and what they are doing
   without calling a tool, and without paying tokens every turn.
2. **Collision warnings at the moment they matter.** "Someone else edited
   this file 3 minutes ago" when I edit it, not after the merge conflict.
3. **Claims.** Announce "I hold the GPU / this worktree / the daemon" in
   one call; see other sessions' claims before doing something expensive.
4. **Wake me when X.** When a peer goes idle, ends, or releases a claim.
   One-shot, no polling, no sleeping.
5. **Ask and get an answer back asynchronously.** An ask wakes the peer;
   their reply wakes me. Reach peers by callsign, id prefix, or by what
   they are doing ("axon").
6. **No spam, no loops.** FYIs never wake anyone. Replies end a
   thread unless they ask something new. Hop cap per thread, wake rate
   limit per pair, do-not-disturb.

## Tools (4, small schemas)

| Tool | Does |
|---|---|
| `comms_who(thread?)` | Roster (callsign, busy/idle, doing, status, claims, cwd), your unread, or one thread. |
| `comms_send(to?, text, ask?, re?, urgent?)` | Tell (quiet), ask (wakes), reply (`re=<id>`, wakes the asker; `to` defaults to the sender). `to="all"` broadcasts quietly. |
| `comms_status(text?, claim?, release?, dnd?, name?)` | Your one-liner, advisory claims (with conflicts reported), do-not-disturb, callsign. |
| `comms_watch(peer?, claim?)` | One-shot wake when a peer goes idle/ends, or when a claim is free. |

Workers/subagents (no session id) can read the roster but not send.

## Delivery

- **Wake** = write one event JSON straight to the target session's event
  socket (from the run registry). No subprocess, no `synaps send`.
  The event text carries sender, id, and the exact reply call.
- **Quiet** = stored; shown in the recipient's next-turn digest.
- Busy recipient: the event steers the running turn; idle: it starts one.

## Awareness without token burn

`before_message` injects a digest only when something changed for that
session: unread quiet messages, peers joined/left, claims or status
changed. Activity churn (`doing`) never triggers it. Most turns inject
nothing. Session start appends a ~60-token primer to the system prompt once
(cache-stable); sessions that predate the plugin get it once via the digest.

## Sources of truth

- **Liveness:** the session run registry (`<base>/run/*.json`) plus a pid
  check. Busy: `<base>/sessions/<id>.turn` exists, else hook state.
- **Doing:** `before_tool_call` (tool + short arg), `before_message`
  (prompt prefix, `share_prompts`), `on_message_complete` (turn end).
- **Caller identity:** `tool.call` `params.session_id` (SynapsCLI
  `feat/extension-session-context`). Older hosts: matched against the
  `before_tool_call` that preceded the call (same tool + same input, FIFO).
- **State:** one SQLite WAL file shared by every plugin process (daemon +
  standalone sessions).

## Cost

One process per daemon. Hooks answer in well under a millisecond; there
is no network and no subprocess. Roster scans are cached for 2 s. The
after_tool_call hook is subscribed for `edit`/`write` only.

## Safety

- Hop cap per thread (6).
- Wake rate limit per sender→recipient (4 per 2 min); messages over the
  limit are downgraded to quiet.
- Broadcasts are quiet unless urgent, and urgent broadcasts are limited
  to 1 per 10 min.
- Messages are capped at 2000 characters.
- The run directory is checked before any socket connect.
- Every hook fails open: if the plugin errors, the session continues.
