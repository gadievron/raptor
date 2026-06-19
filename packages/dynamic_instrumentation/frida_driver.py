"""In-sandbox Frida driver - runs as the PARENT that spawns the target.

Invoked by ``runner.py`` *inside* the sandbox namespace so that the driver
and the target it spawns live in the same process tree (ptrace_scope=1
authorises a parent→descendant trace, the same model gdb/rr use under
``/crash-analysis``). Reads a RAPTOR-authored agent script, spawns the
target suspended, loads the agent, resumes, and streams ``send()`` messages
to a JSONL file until the target exits or the timeout fires.

stdout contract (parsed by the runner):
  ``FRIDA_RESULT=<json>`` - one line with {events, exit, error}.

This file is intentionally dependency-free (only ``frida`` + stdlib) so it
runs under the sandbox's restricted environment.
"""

import argparse
import json
import sys
import time


def main() -> int:
    ap = argparse.ArgumentParser(description="RAPTOR in-sandbox Frida driver")
    ap.add_argument("--agent", required=True, help="Path to the Frida agent JS")
    ap.add_argument("--events-out", required=True, help="JSONL output path")
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("cmd", nargs=argparse.REMAINDER,
                    help="target binary + args (after --)")
    args = ap.parse_args()

    cmd = args.cmd
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        print('FRIDA_RESULT=' + json.dumps({"error": "no target command"}))
        return 2

    try:
        import frida
    except Exception as e:  # noqa: BLE001
        print('FRIDA_RESULT=' + json.dumps(
            {"error": f"frida import failed: {e}"}))
        return 3

    try:
        agent_src = open(args.agent).read()
    except OSError as e:
        print('FRIDA_RESULT=' + json.dumps({"error": f"agent read: {e}"}))
        return 4

    events = []

    def on_message(message, data):
        # 'send' → payload from the agent; 'error' → JS exception. Keep both
        # so the caller can see agent-side failures rather than silent zero.
        events.append(message)

    detached = {"flag": False}

    try:
        pid = frida.spawn(cmd)
        session = frida.attach(pid)
        session.on("detached", lambda *a: detached.update(flag=True))
        script = session.create_script(agent_src)
        script.on("message", on_message)
        script.load()
        frida.resume(pid)
    except Exception as e:  # noqa: BLE001 - spawn/attach can fail (namespace,
        # ptrace_scope, missing target). Report so the runner can fall back.
        print('FRIDA_RESULT=' + json.dumps(
            {"error": f"{type(e).__name__}: {e}"}))
        return 5

    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline and not detached["flag"]:
        time.sleep(0.05)

    try:
        frida.kill(pid)
    except Exception:  # noqa: BLE001 - already dead is fine
        pass

    try:
        with open(args.events_out, "w") as fh:
            for e in events:
                fh.write(json.dumps(e) + "\n")
    except OSError as e:
        print('FRIDA_RESULT=' + json.dumps({"error": f"events write: {e}"}))
        return 6

    n_send = sum(1 for e in events if e.get("type") == "send")
    n_err = sum(1 for e in events if e.get("type") == "error")
    print('FRIDA_RESULT=' + json.dumps(
        {"events": len(events), "send": n_send, "errors": n_err,
         "exited": detached["flag"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
