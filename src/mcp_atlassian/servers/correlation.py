"""Correlation ID middleware for request tracing.

Generates a unique correlation ID per incoming HTTP request, sets it in
``request.state.correlation_id`` for application use, propagates it to the
response headers and enriches structured logs.

Secrets MUST NOT be logged. The correlation ID is a random UUID4 hex string.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

_HEADER_NAME = "X-Correlation-ID"
_logger = logging.getLogger("mcp-atlassian.correlation")


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """ASGI middleware that attaches a per-request correlation ID."""

    def __init__(self, app, header_name: str = _HEADER_NAME) -> None:  # type: ignore[override]  # noqa: ANN401
        super().__init__(app)
        self.header_name = header_name

    async def dispatch(self, request: Request, call_next) -> Response:  # type: ignore[override]  # noqa: ANN001
        correlation_id = request.headers.get(self.header_name) or uuid.uuid4().hex
        # Expose in request.state for handlers / services
        request.state.correlation_id = correlation_id
        # Enrich log records
        extra: dict[str, Any] = {"correlation_id": correlation_id}
        response: Response
        # Log with correlation context if structlog is available; otherwise fallback.
        try:
            import structlog  # noqa: WPS433

            with _logger.contextualize(**extra):  # type: ignore[attr-defined]
                response = await call_next(request)
        except Exception:  # structlog absent or logger lacks contextualize
            _logger.debug("request", extra=extra)
            response = await call_next(request)
        response.headers[self.header_name] = correlation_id
        return response
