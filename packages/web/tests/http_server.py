"""HTTP serving threads owned by unittest or pytest cleanup callbacks."""

import threading


def _stop_serving(server, thread):
    try:
        server.shutdown()
    finally:
        thread.join(timeout=5)
        if thread.is_alive():
            raise RuntimeError("HTTP fixture serving thread did not stop")


def start_http_server(server, add_cleanup):
    """Register ownership before starting a serving loop; return its thread."""
    add_cleanup(server.server_close)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    add_cleanup(_stop_serving, server, thread)
    return thread
