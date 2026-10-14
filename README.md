# agent-comms

Session awareness for [Synaps](https://github.com/HaseebKhalid1507/SynapsCLI). Every live session on the machine can see the others and message them. Each roster entry shows:

- whether that session is busy or idle
- what it is doing right now
- which shared resources it has claimed

A question wakes the peer it's sent to; their reply wakes you back. A plain FYI waits quietly until the recipient's next turn.

The name is a placeholder.

## Tools

| Tool | What it does |
|---|---|
| `comms_who(thread?)` | Lists live sessions (callsign, busy/idle, what they're doing, status, claims, cwd) and your unread messages. Pass `thread` to show one conversation instead. |
| `comms_send(to?, text, ask?, re?, urgent?)` | A quiet tell by default. `ask=true` wakes the recipient. `re=<id>` replies to a message and wakes the asker; `to` can be left out. `to="all"` broadcasts quietly. |
| `comms_status(text?, claim?, release?, dnd?, name?)` | Sets your status line, claims or releases shared resources (`gpu`, a repo path, `daemon`), toggles do-not-disturb, or changes your callsign. Claims are advisory and report conflicts. |
| `comms_watch(peer?, claim?)` | Wakes you once when a peer goes idle or ends, or when a claim is released. |

`to` takes a callsign, a session-id prefix, or a word from what the peer is doing (`to="axon"` reaches whoever is working on Axon).

## What you get without calling anything

- **A digest before a turn, only when something changed.** It lists unread FYIs, peers that joined or left, and claim or status changes. Turns with nothing new inject nothing, so it costs no tokens.
- **Edit collision warnings.** When you `edit` or `write` a file that another live session edited in the last 30 minutes, the tool result says so and names that session.
- **A short primer once per session**, appended to the system prompt.

## Limits

- 6 messages per thread.
- 4 wakes per 2 minutes per sender→recipient pair; anything over that is delivered quietly.
- Broadcasts are quiet unless marked urgent, and an urgent broadcast is allowed once every 10 minutes.
- Do-not-disturb holds asks until the next turn.
- Workers and subagents can read the roster but can't send.

## Cost

- One Python process (stdlib only) and one SQLite WAL file.
- Hooks answer in about 0.05 ms, with no network and no subprocess.
- A wake writes a single event JSON straight to the target session's socket in `~/.synaps-cli/run/`.
- The roster scan (a directory listing plus a pid check) is cached for 2 s.

## Requirements

On SynapsCLI builds where `tool.call` carries `params.session_id` (`feat/extension-session-context`), the plugin uses that to identify the calling session.

On older builds it matches each `tool.call` against the `before_tool_call` hook that came just before it, using the tool name and input. This is correct except when two sessions call the same tool with identical input at the same moment.

## For humans

```sh
python3 main.py who                    # roster
python3 main.py send <to> "text" --ask # message a session (wakes it)
python3 main.py log -n 20              # recent messages
```

## Tests

```sh
python3 tests/test_comms.py
```

The tests use a sandbox base directory with real Unix-socket fake sessions and never touch `~/.synaps-cli`.

See `DESIGN.md` for the reasoning behind each part.
