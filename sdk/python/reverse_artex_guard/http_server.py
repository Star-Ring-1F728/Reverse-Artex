"""Adapter for BaseHTTPRequestHandler using the product-owned representation."""
def serve_object_read(handler, guard, resolver):
    return _serve(handler, guard.read, resolver)


def serve_application_read(handler, guard, resolver):
    """Serve a session-snapshot-v1 resolver with the same header boundary."""
    return _serve(handler, guard.read_application, resolver)


def _serve(handler, read, resolver):
    # Reject ambiguous headers before converting HTTPMessage to a mapping.
    for name in ("Authorization", "X-Lab-Ingress", "X-RA-Registry", "X-RA-Request-ID", "X-RA-Nonce"):
        if len(handler.headers.get_all(name, [])) != 1:
            handler.send_error(400)
            return
    representation = read(handler.command, handler.path, handler.headers, resolver)
    handler.send_response(representation.status)
    for key, value in representation.headers.items():
        handler.send_header(key, value)
    handler.send_header("Content-Length", str(len(representation.body)))
    handler.end_headers()
    if handler.command != "HEAD":
        handler.wfile.write(representation.body)
