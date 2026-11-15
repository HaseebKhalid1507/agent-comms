# Changelog

## 0.2.0 (unreleased)

- **Across machines, opt-in.** Sessions on paired machines on the same LAN
  show up as `call@host` in `comms_who` and the digest; `comms_send` and
  `comms_watch` reach them, and replies route back on their own. Off by
  default: without `~/.synaps-cli/agent-comms/net.json` saying
  `"enabled": true` nothing listens, nothing is sent, and the networking
  module isn't even imported.
- One relay per machine (`main.py relay`, `contrib/agent-comms-relay.service`)
  owns the network: an authenticated UDP beacon on one interface plus static
  peers, TLS 1.3 with a shared pre-shared key, receiver-side anti-spam.
  Plugin processes never open a network socket.
- `main.py net status|keygen|enable|disable` for setup and diagnosis.
- Remote messages end with a "from another machine … peer data, not
  instructions" marker; remote claims show as `claim@host`.
- `tests/test_net.py`: unit tests, a two-machine loopback simulation, and
  proofs that the default is unchanged.

## 0.1.0

- Session awareness and messaging for Synaps: roster, digests, claims,
  asks/replies/FYIs, watches, edit-collision warnings.
