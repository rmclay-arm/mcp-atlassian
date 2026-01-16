"""Exception types raised by the central OAuth core.

Only lightweight, **data-carrying** exceptions live here so that web/CLI layers
can transform them into HTTP responses or user-friendly messages.
"""

from __future__ import annotations


class NeedsReauthError(RuntimeError):
    """Raised when the access token is invalid and a new OAuth flow is required."""

    def __init__(
        self,
        *,
        auth_txn_id: str,
        product: str,
        message: str | None = None,
    ) -> None:
        super().__init__(message or "Re-authentication required.")
        self.auth_txn_id: str = auth_txn_id
        self.product: str = product

    def to_payload(self) -> dict[str, str]:
        """Return a JSON-serialisable payload **without secrets**."""
        return {
            "error": "needs_reauth",
            "auth_txn_id": self.auth_txn_id,
            "product": self.product,
            "message": str(self),
        }
