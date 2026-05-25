"""Pre-fix fixture: CWE-78 command injection (the vulnerability)."""
import os

from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host")
    os.system("ping -c 1 " + host)  # tainted host -> os.system (real CWE-78)
    return "ok"
