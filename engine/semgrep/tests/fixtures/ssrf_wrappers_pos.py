import flask
import requests


def proxy():
    parts = ["http://"]
    parts.append(flask.request.args.get("host"))
    parts.append("/data")
    url = "".join(parts)
    return requests.get(url)
