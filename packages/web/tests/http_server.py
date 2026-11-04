"""HTTP serving threads owned by unittest or pytest cleanup callbacks."""

import threading


def _stop_serving(server, thread):
    # shutdown() waits forever if serve_forever() never started.
    if thread.ident is None:
        return
    try:
        server.shutdown()
    finally:
        thread.join(timeout=5)
        if thread.is_alive():
            raise RuntimeError("HTTP fixture serving thread did not stop")


def start_http_server(server, add_cleanup):
    """Register ownership before starting a serving loop; return its thread."""
    try:
        add_cleanup(server.server_close)
    except BaseException:
        server.server_close()
        raise
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    add_cleanup(_stop_serving, server, thread)
    thread.start()
    return thread
