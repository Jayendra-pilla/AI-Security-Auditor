"""
Request logging middleware for FastAPI.

Generates a unique request ID per request, measures duration,
logs structured request/response data, and injects X-Request-ID header.
"""
import time
import uuid
import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.observability.context import request_id_var, user_id_var

logger = logging.getLogger(__name__)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware that provides request tracing and structured request logging.

    Features:
        - Generates or re-uses X-Request-ID
        - Measures request duration
        - Logs method, path, status_code, duration_ms
        - Injects X-Request-ID into response headers
        - Attempts best-effort user_id extraction from Authorization header
    """

    def __init__(self, app, enable_logging: bool = True):
        super().__init__(app)
        self.enable_logging = enable_logging

    async def dispatch(self, request: Request, call_next) -> Response:
        # Generate or re-use request ID
        req_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request_id_var.set(req_id)

        # Best-effort user_id extraction from JWT (no auth enforcement)
        self._extract_user_id(request)

        start_time = time.perf_counter()

        try:
            response = await call_next(request)
        except Exception:
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            if self.enable_logging:
                logger.error(
                    "Request failed: %s %s | duration_ms=%.2f | request_id=%s",
                    request.method, request.url.path, duration_ms, req_id,
                )
            raise

        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

        # Inject X-Request-ID into response
        response.headers["X-Request-ID"] = req_id

        if self.enable_logging:
            logger.info(
                "Request completed: %s %s | status=%d | duration_ms=%.2f | request_id=%s | user_id=%s",
                request.method,
                request.url.path,
                response.status_code,
                duration_ms,
                req_id,
                user_id_var.get("-"),
            )

        return response

    @staticmethod
    def _extract_user_id(request: Request) -> None:
        """
        Best-effort extraction of user_id from JWT Authorization header.
        Does NOT enforce authentication — silently skips on any failure.
        """
        try:
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                import base64
                import json as _json

                token = auth_header[7:]
                # Decode JWT payload (second segment) without verification
                payload_b64 = token.split(".")[1]
                # Add padding
                padding = 4 - len(payload_b64) % 4
                if padding != 4:
                    payload_b64 += "=" * padding
                payload = _json.loads(base64.urlsafe_b64decode(payload_b64))
                uid = payload.get("sub", "-")
                user_id_var.set(str(uid))
        except Exception:
            pass
