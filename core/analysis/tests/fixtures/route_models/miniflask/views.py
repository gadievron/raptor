"""Cross-file receiver: the app object is imported, not constructed
here — resolution goes through the package-scope registry."""
from miniflask.app import app


@app.route("/cross")
def cross():
    return 1
