"""Run main.py under an audit hook that records every socket it creates,
binds or connects, and whether comms_net was ever imported.
Usage: AC_AUDIT_LOG=/path python3 audit_run.py /path/to/main.py [args...]
"""
import atexit
import json
import os
import runpy
import sys

LOG = os.environ["AC_AUDIT_LOG"]
MAIN = sys.argv[1]


def write(rec):
    with open(LOG, "a") as f:
        f.write(json.dumps(rec) + "\n")


def hook(event, args):
    if event == "socket.__new__":
        write(["new", int(args[1])])
    elif event in ("socket.bind", "socket.connect"):
        addr = args[1]
        write([event.split(".")[1], addr if isinstance(addr, str) else list(addr) if isinstance(addr, tuple) else repr(addr)])


sys.addaudithook(hook)
atexit.register(lambda: write(["comms_net_imported", "comms_net" in sys.modules]))
sys.argv = [MAIN] + sys.argv[2:]
sys.path.insert(0, os.path.dirname(os.path.abspath(MAIN)))
runpy.run_path(MAIN, run_name="__main__")
