"""Post-fix fixture: neutralized by a PROJECT-SPECIFIC allowlist that CodeQL
does not model as a barrier — so CodeQL still flags it (a real
``missing_sanitizer_model`` false positive, the trust sound-tier target)."""
import os

from flask import Flask, request

app = Flask(__name__)


def host_is_allowed(h):
    return h in ("localhost", "127.0.0.1")


@app.route("/ping")
def ping():
    host = request.args.get("host")
    if not host_is_allowed(host):
        return "rejected"
    os.system("ping -c 1 " + host)  # neutralized by host_is_allowed()
    return "ok"
