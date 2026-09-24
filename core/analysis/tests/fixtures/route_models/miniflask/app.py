"""Flask fixture: decorator, verb-shortcut, blueprint-prefix,
method-call, and dynamic registrations. Never imported by tests —
parsed statically only."""
from flask import Blueprint, Flask

app = Flask(__name__)
admin = Blueprint("admin", __name__, url_prefix="/admin")

BASE = "/computed"


def require_auth(f):
    return f


@app.route("/users/<int:uid>", methods=["GET", "POST"])
@require_auth
def user(uid):
    return uid


@app.get("/health")
def health():
    return "ok"


@admin.route("/panel")
def panel():
    return "panel"


@app.route(BASE + "/dyn")
def dyn():
    return "dyn"


def legacy_view():
    return "legacy"


app.add_url_rule("/legacy", "legacy", view_func=legacy_view)
