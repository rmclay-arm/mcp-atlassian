"""Typed, immutable records used by central OAuth logic."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

from mcp_atlassian.central_auth.clock import Clock, default_clock


@dataclass(frozen=True, slots=True)
class AuthTxnRecord:
    """Metadata captured when kicking-off a browser-based OAuth flow."""

    auth_txn_id: str
    client_id: str
    redirect_uri: str
    product: str
    code_verifier: str
    code_challenge: str
    # New fields for link-code binding & instance scoping (Phase-1 LiveFix)
    binding_id: str = "default"
    instance_id: str = "default"
    created_at: int = field(default_factory=lambda: int(default_clock()))
    # The transaction is considered stale after 15 minutes by default
    ttl_seconds: int = 900

    def is_expired(self, *, clock: Clock = default_clock) -> bool:
        """Return *True* if the transaction exceeded its TTL."""
        return (clock() - self.created_at) > self.ttl_seconds


@dataclass(frozen=True, slots=True)
class TokenRecord:
    """Snapshot of an OAuth access/refresh token pair."""

    access_token: str
    expires_at: int
    obtained_at: int
    refresh_token: str | None = None
    cloud_id: str | None = None
    instance_url: str | None = None

    @property
    def ttl(self) -> int:
        """Seconds between *obtained_at* and *expires_at*."""
        return self.expires_at - self.obtained_at
