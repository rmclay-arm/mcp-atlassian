"""Structured logging helpers for central OAuth components.

This module purposefully restricts **which** contextual attributes are attached
to log records in order to avoid accidentally leaking secrets.  All helpers
ONLY inject the following *non-sensitive* fields:

- ``auth_txn_id``  – The OAuth transaction identifier (first 8 chars kept)
- ``instance_id``  – Internal identifier for the running MCP instance
- ``product``      – Product being authorised (``jira``, ``confluence``…)
- ``correlation_id`` – Placeholder, to be wired by outer layers later on

Usage
-----
>>> from mcp_atlassian.central_auth.log_utils import get_auth_logger
>>> log = get_auth_logger(
...     base_logger_name="mcp-atlassian.central_auth.oauth",
...     auth_txn_id="123e4567-e89b-12d3-a456-426614174000",
...     instance_id="agent-alpha",
...     product="confluence",
... )
>>> log.info("Starting OAuth flow")
INFO mcp-atlassian.central_auth.oauth auth_txn_id=123e4567 product=confluence ...

The adapter is a thin wrapper around :class:`logging.LoggerAdapter`.
"""

from __future__ import annotations

import logging
from typing import Any, Mapping, MutableMapping


class _AuthLoggerAdapter(logging.LoggerAdapter):
    """Inject whitelisted auth context into log records."""

    extra_keys = ("auth_txn_id", "instance_id", "product", "correlation_id")

    def __init__(self, logger: logging.Logger, extra: Mapping[str, Any] | None = None):
        extra_clean: MutableMapping[str, Any] = {}
        for k in self.extra_keys:
            if k == "auth_txn_id" and extra and "auth_txn_id" in extra:
                # keep only first 6 characters to avoid storing the full UUID
                extra_clean[k] = str(extra["auth_txn_id"])[:6]
            elif extra and k in extra and extra[k] is not None:
                extra_clean[k] = extra[k]
        super().__init__(logger, extra_clean)

    def process(self, msg: str, kwargs: MutableMapping[str, Any]):
        if "extra" not in kwargs or kwargs["extra"] is None:
            kwargs["extra"] = {}
        # merge but do not overwrite call-site provided extras
        for k, v in self.extra.items():
            kwargs["extra"].setdefault(k, v)
        return msg, kwargs


def get_auth_logger(
    *,
    base_logger_name: str = "mcp-atlassian.central_auth",
    auth_txn_id: str | None = None,
    instance_id: str | None = None,
    product: str | None = None,
    correlation_id: str | None = None,
) -> logging.LoggerAdapter:
    """Return a LoggerAdapter pre-filled with auth context."""
    logger = logging.getLogger(base_logger_name)
    return _AuthLoggerAdapter(
        logger,
        {
            "auth_txn_id": auth_txn_id,
            "instance_id": instance_id,
            "product": product,
            "correlation_id": correlation_id,
        },
    )
