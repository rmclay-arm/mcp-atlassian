"""CentralAuthService – phase-1 skeleton.

This service encapsulates the *business logic* for browser-based OAuth
flows.  Handlers in ``mcp_atlassian.servers.auth`` call the thin façade
methods below.

Phase-1 focuses on plumbing the HTTP layer; the heavy lifting
(token exchange, refresh, storage, renewal, etc.) will be completed in
upcoming milestones.

For now **all secrets are redacted** from logs and only single-instance
environment variables are consulted (``*_OAUTH_CLIENT_ID``,
``*_OAUTH_CLIENT_SECRET``, etc.).
"""

from __future__ import annotations

import logging
import os
import uuid
from typing import Final, Literal, Any

from mcp_atlassian.central_auth.models import AuthTxnRecord, TokenRecord
from mcp_atlassian.central_auth.pkce import code_challenge_s256, generate_code_verifier
from mcp_atlassian.central_auth.state import build_state, parse_state
from mcp_atlassian.central_auth.store import AuthStore, default_store
from mcp_atlassian.utils.logging import mask_sensitive

_LOG = logging.getLogger("mcp-atlassian.central_auth.service")

Product = Literal["jira", "confluence"]

# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #
_AUTH_URLS: dict[Product, str] = {
    "jira": os.getenv("JIRA_OAUTH_AUTHORIZE_URL", "").rstrip("/"),
    "confluence": os.getenv("CONFLUENCE_OAUTH_AUTHORIZE_URL", "").rstrip("/"),
}

_CLIENT_IDS: dict[Product, str] = {
    "jira": os.getenv("JIRA_OAUTH_CLIENT_ID", ""),
    "confluence": os.getenv("CONFLUENCE_OAUTH_CLIENT_ID", ""),
}

_CLIENT_SECRETS: dict[Product, str] = {
    "jira": os.getenv("JIRA_OAUTH_CLIENT_SECRET", ""),
    "confluence": os.getenv("CONFLUENCE_OAUTH_CLIENT_SECRET", ""),
}

_SCOPE_DEFAULTS: dict[Product, str] = {
    "jira": "read:jira-user read:jira-work write:jira-work",
    "confluence": "read:confluence-content write:confluence-content",
}

_REDIRECT_URIS: dict[Product, str] = {
    "jira": os.getenv("JIRA_OAUTH_REDIRECT_URI", ""),
    "confluence": os.getenv("CONFLUENCE_OAUTH_REDIRECT_URI", ""),
}


def _ensure_product(product: Product) -> None:
    if product not in ("jira", "confluence"):
        raise ValueError("unsupported product")


# --------------------------------------------------------------------------- #
# Public service                                                              #
# --------------------------------------------------------------------------- #
class CentralAuthService:
    """Application service orchestrating OAuth web-flows (phase-1 subset)."""

    _STATE_SECRET_ENV: Final[str] = "MCP_STATE_HMAC_SECRET"

    def __init__(self, store: AuthStore | None = None) -> None:
        self.store = store or default_store()
        state_secret = os.getenv(self._STATE_SECRET_ENV)
        if not state_secret:
            # Generate ephemeral secret – suitable for containerized single-instance dev setups
            state_secret = uuid.uuid4().hex
            _LOG.warning(
                "Environment variable %s not set – generated transient secret. "
                "State validation will break after process restart.",
                self._STATE_SECRET_ENV,
            )
        # Store as non-optional str to satisfy type checkers
        self._state_secret: str = state_secret

    # ------------------------------------------------------------------ #
    # Public API called by HTTP handlers                                 #
    # ------------------------------------------------------------------ #
    # Link codes – future mobile hand-off feature (not used yet)
    def create_link_code(self, *, ttl_seconds: int = 600) -> str:
        """Return a one-time link code (random URL-safe token)."""
        return self.store.create_link_code(ttl_seconds=ttl_seconds)

    # Browser-based flow
    def build_authorize_url(  # noqa: C901 – simple validation then assembly
        self,
        *,
        product: Product,
        instance_id: str,
        redirect_uri: str,
        scope: str | None = None,
    ) -> str:
        """Return the provider authorize URL (with PKCE & state)."""
        _ensure_product(product)

        authorize_base = _AUTH_URLS[product]
        client_id = _CLIENT_IDS[product]
        if not authorize_base or not client_id:
            raise ValueError(f"{product} OAuth environment not configured")

        # PKCE
        code_verifier = generate_code_verifier()
        challenge = code_challenge_s256(code_verifier)

        # Store transaction
        auth_txn_id = uuid.uuid4().hex
        txn = AuthTxnRecord(
            auth_txn_id=auth_txn_id,
            client_id=client_id,
            redirect_uri=redirect_uri,
            product=product,
            code_verifier=code_verifier,
            code_challenge=challenge,
        )
        self.store.create_auth_txn(txn)

        state = build_state(auth_txn_id, self._state_secret)
        scope_val = scope or _SCOPE_DEFAULTS[product]

        url = (
            f"{authorize_base}"
            f"?audience=api.atlassian.com"  # Atlassian specific
            f"&client_id={client_id}"
            f"&scope={scope_val}"
            f"&redirect_uri={redirect_uri}"
            f"&state={state}"
            f"&response_type=code"
            f"&code_challenge={challenge}"
            f"&code_challenge_method=S256"
        )

        _LOG.debug(
            "Built authorize URL for txn=%s**** state=%s****",
            auth_txn_id[:6],
            mask_sensitive(state, 6),
        )
        return url

    def exchange_code(self, *, product: Product, code: str, state: str) -> None:
        """Exchange *code* for tokens. Phase-1 stub stores placeholder token."""
        _ensure_product(product)

        # Validate state & load txn
        auth_txn_id, _ = parse_state(state, self._state_secret)
        txn = self.store.consume_auth_txn(auth_txn_id, state)
        if not txn:
            raise ValueError("invalid or expired transaction")

        # Phase-1: DO NOT call real token endpoint – store placeholder
        token = f"demo-{uuid.uuid4().hex}"
        token_rec = TokenRecord(
            access_token=token,
            refresh_token=None,
            obtained_at=0,
            expires_at=2**31 - 1,
            cloud_id="demo",
            instance_url="https://example.atlassian.net",
        )
        self.store.save_tokens(
            binding_id="default",
            product=product,
            instance_id="default",
            token_record=token_rec,
        )
        _LOG.info("Stored placeholder token for product=%s txn=%s", product, auth_txn_id)

    def get_binding_status(self, *, instance_id: str) -> dict[str, Any]:  # noqa: ANN401
        """Return dummy binding status until real tokens implemented."""
        return {
            "instance_id": instance_id,
            "jira": bool(
                self.store.load_tokens("default", "jira", instance_id) is not None
            ),
            "confluence": bool(
                self.store.load_tokens("default", "confluence", instance_id)
                is not None
            ),
        }

    def disconnect(self, *, product: Product, instance_id: str) -> None:
        """Delete stored tokens."""
        self.store.delete_tokens("default", product, instance_id)
        _LOG.debug("Deleted tokens product=%s instance=%s", product, instance_id)
