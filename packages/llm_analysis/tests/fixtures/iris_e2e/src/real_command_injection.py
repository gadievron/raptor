"""Real dataflow: HTTP request input flows to subprocess.

Flask treats request args as a RemoteFlowSource — exactly the source
class CodeQL's prebuilt CommandInjectionFlow looks for. Both Semgrep
(pattern match) and CodeQL (taint tracking) should agree this is real.
"""

import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def run_cmd():
    # Source: Flask request.args is a RemoteFlowSource.
    # Sink: subprocess.call with shell=True, argument 0.
    # No sanitization — straight pipe from network input to shell.
    cmd = request.args.get("cmd", "")
    return str(subprocess.call(cmd, shell=True))


if __name__ == "__main__":
    app.run()
