#!/usr/bin/env python3
"""End-to-end tests for agent-comms: drive main.py over JSON-RPC against a
sandbox base dir with real Unix-socket "sessions" that capture wake events.
Never touches ~/.synaps-cli. Run: python3 tests/test_comms.py
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAIN = os.path.join(ROOT, "main.py")
PLUGIN = "agent-comms"


class FakeSession:
    """A registered 'session': registry JSON + a listening event socket."""

    def __init__(self, base, sid):
        self.sid = sid
        self.events = []
        run = os.path.join(base, "run")
        self.sock_path = os.path.join(run, f"s-{sid[-4:]}.sock")
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(self.sock_path)
        self.srv.listen(8)
        self.reg = os.path.join(run, f"{sid}.json")
        with open(self.reg, "w") as f:
            json.dump({"kind": "session", "session_id": sid, "name": None,
                       "socket_path": self.sock_path, "pid": os.getpid(),
                       "started_at": "2026-10-14T05:00:00Z"}, f)
        self.thread = threading.Thread(target=self._accept, daemon=True)
        self.thread.start()

    def _accept(self):
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            data = b""
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                data += chunk
            conn.close()
            self.events.append(json.loads(data))

    def texts(self):
        return [e["content"]["text"] for e in self.events]

    def kill(self):
        if os.path.exists(self.reg):
            os.unlink(self.reg)
        self.srv.close()


class Plugin:
    def __init__(self, base):
        self.p = subprocess.Popen([sys.executable, MAIN], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=ROOT)
        self.n = 0
        self.base = base

    def call(self, method, params):
        self.n += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self.n, "method": method, "params": params}).encode()
        self.p.stdin.write(b"Content-Length: %d\r\n\r\n" % len(body) + body)
        self.p.stdin.flush()
        length = None
        while True:
            line = self.p.stdout.readline()
            if line in (b"\r\n", b"\n"):
                break
            k, _, v = line.decode().partition(":")
            if k.lower() == "content-length":
                length = int(v)
        msg = json.loads(self.p.stdout.read(length))
        assert msg["id"] == self.n, msg
        if "error" in msg:
            raise RuntimeError(msg["error"])
        return msg["result"]

    def hook(self, kind, sid, **kw):
        ev = {"kind": kind, "tool_name": None, "tool_runtime_name": None, "tool_input": None,
              "tool_output": None, "message": None, "session_id": sid, "transcript": None, "data": None}
        ev.update(kw)
        return self.call("hook.handle", ev)

    def stamp(self, name, sid, inp):
        """What the host does: before_tool_call, apply a modify, return the input tool.call gets."""
        r = self.hook("before_tool_call", sid, tool_name=f"{PLUGIN}_{name}",
                      tool_runtime_name=f"{PLUGIN}:{name}", tool_input=inp)
        return r["input"] if r["action"] == "modify" else inp

    def tool(self, name, sid, **inp):
        return self.call("tool.call", {"name": name, "input": self.stamp(name, sid, inp)})["content"]

    def close(self):
        try:
            self.call("shutdown", {})
        except Exception:
            pass
        self.p.wait(timeout=5)
        for f in (self.p.stdin, self.p.stdout, self.p.stderr):
            f.close()


def settle():
    time.sleep(0.05)


class CommsTest(unittest.TestCase):
    def setUp(self):
        self.base = tempfile.mkdtemp(prefix="agent-comms-test-")
        os.makedirs(os.path.join(self.base, "run"))
        os.makedirs(os.path.join(self.base, "sessions"))
        self.A = FakeSession(self.base, "20261014-000001-aaaa")
        self.B = FakeSession(self.base, "20261014-000002-bbbb")
        self.pl = Plugin(self.base)
        init = self.pl.call("initialize", {"plugin_id": "agent-comms", "plugin_root": ROOT,
                                           "config": {"base_dir": self.base}})
        self.assertEqual([t["name"] for t in init["capabilities"]["tools"]],
                         ["comms_who", "comms_send", "comms_status", "comms_watch"])
        self.callA = self.pl.hook("on_session_start", self.A.sid)["content"].split("'")[1]
        self.callB = self.pl.hook("on_session_start", self.B.sid)["content"].split("'")[1]

    def tearDown(self):
        self.pl.close()
        for s in (self.A, self.B):
            s.srv.close()
        shutil.rmtree(self.base, ignore_errors=True)

    def test_roster_shows_peers_and_activity(self):
        self.assertNotEqual(self.callA, self.callB)
        self.pl.hook("before_message", self.A.sid, message="port the jigjig patch to fe33c3c7")
        self.pl.hook("before_tool_call", self.A.sid, tool_name="bash",
                     tool_input={"command": "cargo test --workspace\nmore"})
        out = self.pl.tool("comms_who", self.B.sid)
        self.assertIn("2 live session(s)", out)
        self.assertIn(f"{self.callB} (you)", out)
        self.assertIn("bash: cargo test --workspace", out)
        self.assertIn("asked: port the jigjig patch", out)

    def test_tell_is_quiet_and_lands_in_next_digest_once(self):
        r = self.pl.tool("comms_send", self.B.sid, to=self.callA, text="FYI pushed PR #226")
        self.assertIn("quiet", r)
        settle()
        self.assertEqual(self.A.events, [])
        d = self.pl.hook("before_message", self.A.sid, message="next")
        self.assertEqual(d["action"], "inject")
        self.assertIn("FYI pushed PR #226", d["content"])
        d2 = self.pl.hook("before_message", self.A.sid, message="again")
        self.assertEqual(d2["action"], "continue", "digest only on change")

    def test_ask_wakes_and_reply_wakes_back(self):
        r = self.pl.tool("comms_send", self.B.sid, to=self.callA, text="done with the GPU?", ask=True)
        self.assertIn("woke them", r)
        settle()
        self.assertEqual(len(self.A.events), 1)
        ev = self.A.events[0]
        self.assertEqual(ev["source"]["source_type"], "agent-comms")
        self.assertEqual(ev["sender"]["name"], self.callB)
        self.assertTrue(ev["expects_response"])
        self.assertIn("done with the GPU?", ev["content"]["text"])
        mid = int(r.split()[0][1:])
        self.assertIn(f"comms_send(re={mid}", ev["content"]["text"])
        # Reply without `to`: goes to the asker and wakes them.
        r2 = self.pl.tool("comms_send", self.A.sid, re=mid, text="yes, released")
        self.assertIn(f"reply → {self.callB}", r2)
        settle()
        self.assertIn("yes, released", self.B.texts()[-1])
        self.assertIn("no response needed", self.B.texts()[-1])
        # Woken messages don't repeat in the digest.
        d = self.pl.hook("before_message", self.B.sid, message="x")
        self.assertNotIn("yes, released", d.get("content", ""))

    def test_claims_conflict_and_claim_watch(self):
        self.pl.tool("comms_status", self.A.sid, text="axon bench", claim=["GPU"])
        r = self.pl.tool("comms_status", self.B.sid, claim=["gpu"])
        self.assertIn(f"also held by {self.callA}", r)
        self.pl.tool("comms_status", self.B.sid, release=["gpu"])
        w = self.pl.tool("comms_watch", self.B.sid, claim="gpu")
        self.assertIn("armed", w)
        self.pl.tool("comms_status", self.A.sid, release=["gpu"])
        settle()
        self.assertTrue(any("claim 'gpu' is free" in t for t in self.B.texts()), self.B.texts())
        self.assertIn("free right now", self.pl.tool("comms_watch", self.B.sid, claim="gpu"))

    def test_peer_watch_fires_on_idle(self):
        self.pl.hook("before_message", self.A.sid, message="go")
        self.pl.tool("comms_watch", self.B.sid, peer=self.callA)
        self.pl.hook("on_message_complete", self.A.sid, message="done", data={"has_tool_use": True})
        settle()
        self.assertEqual(self.B.events, [], "mid-turn message is not idle")
        self.pl.hook("on_message_complete", self.A.sid, message="done", data={"has_tool_use": False})
        settle()
        self.assertTrue(any(f"{self.callA} is idle" in t for t in self.B.texts()))

    def test_edit_collision_warning(self):
        path = os.path.join(self.base, "stream.rs")
        out = self.pl.hook("after_tool_call", self.A.sid, tool_name="edit",
                           tool_input={"path": path}, tool_output="Edited stream.rs")
        self.assertEqual(out["action"], "continue")
        out = self.pl.hook("after_tool_call", self.B.sid, tool_name="edit",
                           tool_input={"path": path}, tool_output="Edited stream.rs")
        self.assertEqual(out["action"], "replace")
        self.assertTrue(out["output"].startswith("Edited stream.rs\n⚠ agent-comms:"))
        self.assertIn(self.callA, out["output"])

    def test_resolve_by_activity(self):
        self.pl.tool("comms_status", self.A.sid, text="axon G4 offload split")
        r = self.pl.tool("comms_send", self.B.sid, to="axon", text="hi")
        self.assertIn(f"→ {self.callA}", r)
        r = self.pl.tool("comms_send", self.B.sid, to="nobody-matches", text="hi")
        self.assertIn("not a live session", r)

    def test_hop_cap(self):
        r = self.pl.tool("comms_send", self.B.sid, to=self.callA, text="q0", ask=True)
        mid = int(r.split()[0][1:])
        sender = [self.A.sid, self.B.sid]
        for i in range(1, 10):
            r = self.pl.tool("comms_send", sender[i % 2], re=mid, text=f"q{i}", ask=True)
            if "hit" in r:
                break
            mid = int(r.split()[0][1:])
        self.assertIn("hops", r)
        self.assertLessEqual(i, 6)

    def test_wake_rate_limit(self):
        res = [self.pl.tool("comms_send", self.B.sid, to=self.callA, text=f"ask {i}", ask=True) for i in range(6)]
        self.assertTrue(all("woke them" in r for r in res[:4]), res)
        self.assertIn("rate limit", res[4])

    def test_dnd_holds_asks_quietly(self):
        self.pl.tool("comms_status", self.A.sid, dnd=True)
        r = self.pl.tool("comms_send", self.B.sid, to=self.callA, text="ping", ask=True)
        self.assertIn("do-not-disturb", r)
        r = self.pl.tool("comms_send", self.B.sid, to=self.callA, text="fire!", urgent=True)
        self.assertIn("woke them", r)

    def test_worker_is_read_only(self):
        self.assertIn("workers can't send", self.pl.tool("comms_send", None, to=self.callA, text="x"))
        self.assertIn("live session", self.pl.tool("comms_who", None))

    def test_concurrent_identical_calls_attribute_correctly(self):
        # Both sessions call comms_who() with identical input; the host runs
        # both hooks before either tool.call, and the calls land out of order.
        a = self.pl.stamp("comms_who", self.A.sid, {})
        b = self.pl.stamp("comms_who", self.B.sid, {})
        out_b = self.pl.call("tool.call", {"name": "comms_who", "input": b})["content"]
        out_a = self.pl.call("tool.call", {"name": "comms_who", "input": a})["content"]
        self.assertIn(f"{self.callB} (you)", out_b)
        self.assertIn(f"{self.callA} (you)", out_a)

    def test_stamp_cannot_be_forged_or_replayed(self):
        # The model supplies its own token: the hook overwrites it.
        inp = self.pl.stamp("comms_send", self.B.sid, {"to": self.callA, "text": "x", "_comms_caller": "forged"})
        self.assertNotEqual(inp["_comms_caller"], "forged")
        r = self.pl.call("tool.call", {"name": "comms_send", "input": dict(inp)})["content"]
        self.assertIn(f"→ {self.callA}", r)
        # Replaying the same token: single-use, so the caller is unknown.
        r = self.pl.call("tool.call", {"name": "comms_send", "input": dict(inp)})["content"]
        self.assertIn("workers can't send", r)
        # No hook ran (e.g. it timed out) and the model forged a token.
        r = self.pl.call("tool.call", {"name": "comms_send",
                                       "input": {"to": self.callA, "text": "x", "_comms_caller": "guess"}})["content"]
        self.assertIn("workers can't send", r)

    def test_host_session_id_on_tool_call_still_works(self):
        r = self.pl.call("tool.call", {"name": "comms_send", "session_id": self.B.sid,
                                       "input": {"to": self.callA, "text": "via params"}})["content"]
        self.assertIn(f"tell → {self.callA}", r)

    def test_other_tools_are_not_modified(self):
        r = self.pl.hook("before_tool_call", self.A.sid, tool_name="bash", tool_input={"command": "ls"})
        self.assertEqual(r["action"], "continue")

    def test_broadcast_is_quiet(self):
        C = FakeSession(self.base, "20261014-000003-cccc")
        r = self.pl.tool("comms_send", self.B.sid, to="all", text="reloading daemon in 5m")
        self.assertIn("quiet", r)
        settle()
        self.assertEqual(self.A.events + C.events, [])
        d = self.pl.hook("before_message", C.sid, message="hi")
        self.assertIn("reloading daemon in 5m", d["content"])
        self.assertIn("You are", d["content"], "late joiner gets the primer once")
        C.kill()

    def test_session_end_releases_claims_and_fires_watches(self):
        self.pl.tool("comms_status", self.A.sid, claim=["daemon"])
        self.pl.tool("comms_watch", self.B.sid, claim="daemon")
        self.pl.tool("comms_watch", self.B.sid, peer=self.callA)
        self.A.kill()
        self.pl.hook("on_session_end", self.A.sid)
        settle()
        texts = self.B.texts()
        self.assertTrue(any("ended" in t for t in texts), texts)
        self.assertTrue(any("claim 'daemon' is free" in t for t in texts), texts)
        self.assertIn("1 live session(s)", self.pl.tool("comms_who", self.B.sid))

    def test_session_without_a_card_is_told_it_is_invisible(self):
        out = self.pl.tool("comms_who", self.A.sid)
        self.assertNotIn("can't see you", out)
        # The card goes; the socket stays up (a refused --continue elsewhere).
        os.unlink(self.A.reg)
        import sqlite3
        con = sqlite3.connect(os.path.join(self.base, "agent-comms", "comms.db"))
        con.execute("UPDATE peers SET first_seen=first_seen-60 WHERE sid=?", (self.A.sid,))
        con.commit()
        con.close()
        out = self.pl.tool("comms_who", self.A.sid)
        self.assertTrue(out.startswith("⚠ Other sessions can't see you"), out)
        self.assertIn(f"{self.A.sid}.json is missing", out)
        r = self.pl.tool("comms_send", self.A.sid, to=self.callB, text="still there?", ask=True)
        self.assertIn("woke them", r)
        self.assertNotIn("their reply will wake you", r)
        self.assertIn("can't see you", r)
        self.assertIn("1 live session(s)", self.pl.tool("comms_who", self.B.sid))
        self.assertNotIn("can't see you", self.pl.tool("comms_who", self.B.sid))

    def test_hook_latency(self):
        n = 300
        t = time.perf_counter()
        for i in range(n):
            self.pl.hook("before_tool_call", self.A.sid, tool_name="bash", tool_input={"command": f"echo {i}"})
        per = (time.perf_counter() - t) / n * 1000
        print(f"\nbefore_tool_call round trip: {per:.3f} ms", file=sys.stderr)
        self.assertLess(per, 5.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
