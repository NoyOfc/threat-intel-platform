from starlette.types import ASGIApp, Receive, Scope, Send

from app.api.errors import error_response

MAX_BODY_BYTES = 1024 * 1024
_BODY_METHODS = frozenset({"POST", "PUT", "PATCH"})


class BodySizeLimitMiddleware:
    """Reject request bodies over a fixed size before the app reads them.

    Requires Content-Length on body-carrying methods; the server enforces that the
    body does not exceed it, so chunked/unknown-length uploads can't bypass the cap.
    """

    def __init__(self, app: ASGIApp, max_bytes: int = MAX_BODY_BYTES) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] not in _BODY_METHODS:
            await self.app(scope, receive, send)
            return

        content_length = dict(scope["headers"]).get(b"content-length")
        if content_length is None:
            response = error_response(411, "length_required", "Content-Length header required.")
        elif not content_length.isdigit():
            response = error_response(400, "bad_request", "Invalid Content-Length header.")
        elif int(content_length) > self.max_bytes:
            response = error_response(
                413, "payload_too_large", f"Request body exceeds {self.max_bytes} bytes."
            )
        else:
            await self.app(scope, receive, send)
            return
        await response(scope, receive, send)
