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
from urllib.parse import urlencode

from pathlib import Path

from mcp_atlassian.central_auth.clock import Clock, default_clock
from mcp_atlassian.central_auth.errors import NeedsReauthError
from mcp_atlassian.utils.oauth import OAuthConfig
from mcp_atlassian.central_auth.store import (
    _file_lock,  # type: ignore
    binding_id_from_link_code,
)

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
    "jira": "WRITE",
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
        link_code: str | None = None,
    ) -> str:
        """Return the provider authorize URL (with PKCE & state)."""
        _ensure_product(product)

        authorize_base = _AUTH_URLS[product]
        client_id = _CLIENT_IDS[product]
        if not authorize_base or not client_id:
            raise ValueError(f"{product} OAuth environment not configured")

        # Derive binding identity from link_code (phase-1 LiveFix)
        binding_id: str = (
            binding_id_from_link_code(link_code) if link_code else "default"
        )

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
            binding_id=binding_id,
            instance_id=instance_id,
        )
        self.store.create_auth_txn(txn)

        state = build_state(auth_txn_id, self._state_secret)
        # Determine scope: explicit arg > ENV > default
        env_scope_key = f"{product.upper()}_OAUTH_SCOPE"
        scope_env = os.getenv(env_scope_key)
        scope_val = scope or scope_env or _SCOPE_DEFAULTS[product]

        query_params: dict[str, str] = {
            "client_id": client_id,
            "scope": scope_val,
            "redirect_uri": redirect_uri,
            "state": state,
            "response_type": "code",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }

        # Include audience only for Atlassian Cloud centralized auth
        if "auth.atlassian.com" in authorize_base:
            query_params["audience"] = "api.atlassian.com"

        url = f"{authorize_base}?{urlencode(query_params)}"

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

        # ------------------------------------------------------------------
        # Real token exchange for Jira/Confluence Data Center OAuth 2.0
        # ------------------------------------------------------------------
        import requests  # local import to avoid mandatory dep for non-OAuth paths

        # Build token endpoint URL (replace '/authorize' with '/token')
        authorize_base = _AUTH_URLS[product]
        if not authorize_base:
            raise ValueError(f"{product} OAuth environment not configured")

        if authorize_base.endswith("/authorize"):
            token_url = authorize_base.rsplit("/authorize", 1)[0] + "/token"
        else:
            token_url = f"{authorize_base.rstrip('/')}/token"

        payload: dict[str, str] = {
            "grant_type": "authorization_code",
            "client_id": txn.client_id,
            "code": code,
            "redirect_uri": txn.redirect_uri,
            "code_verifier": txn.code_verifier,
        }
        client_secret = _CLIENT_SECRETS.get(product) or ""
        if client_secret:
            payload["client_secret"] = client_secret  # noqa: S105

        try:
            resp = requests.post(token_url, data=payload, timeout=(5, 20))
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(f"Token request failed: {exc}") from exc

        if not resp.ok:
            raise ValueError(
                f"Token endpoint returned {resp.status_code}: {resp.text[:200]}"
            )

        data = resp.json()
        access_token = data.get("access_token")
        if not access_token:
            raise ValueError("Token response missing access_token")

        refresh_token = data.get("refresh_token")
        expires_in = int(data.get("expires_in", 3600))
        obtained_at = int(default_clock())
        expires_at = obtained_at + expires_in

        instance_url = authorize_base.split("/rest/", 1)[0]

        token_rec = TokenRecord(
            access_token=access_token,
            refresh_token=refresh_token,
            obtained_at=obtained_at,
            expires_at=expires_at,
            cloud_id=None,
            instance_url=instance_url,
        )
        self.store.save_tokens(
            binding_id=txn.binding_id,
            product=product,
            instance_id=txn.instance_id,
            token_record=token_rec,
        )
        _LOG.info(
            "Exchanged OAuth code for product=%s txn=%s**** (expires in %ss)",
            product,
            auth_txn_id[:6],
            expires_in,
        )

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

    # ------------------------------------------------------------------ #
    # Token access & JIT refresh                                         #
    # ------------------------------------------------------------------ #
    def get_access_token(
        self,
        *,
        binding_id: str,
        product: Product,
        instance_id: str,
        clock: Clock = default_clock,
        grace_seconds: int = 120,
    ) -> str:
        """Return a valid access token, refreshing on-demand.

        Implements single-flight behaviour: only one refresh runs at a time
        per (binding_id, product, instance_id) by leveraging the store’s
        advisory file-lock.  Callers that lose the lock fail fast so upstream
        HTTP handlers can retry shortly.
        """
        _ensure_product(product)

        rec = self.store.load_tokens(binding_id, product, instance_id)
        if rec is None:
            raise NeedsReauthError(
                auth_txn_id=f"missing-{binding_id}",
                product=product,
                message="No stored credentials",
            )

        now = int(clock())
        if (rec.expires_at - now) > grace_seconds:
            return rec.access_token

        # Attempt single-flight refresh
        lock_path: Path = self.store._token_lock(binding_id, product, instance_id)  # type: ignore[attr-defined]
        try:
            with _file_lock(lock_path, retries=0, delay=0):
                # Another thread/process may have refreshed while we waited.
                latest = self.store.load_tokens(binding_id, product, instance_id)
                if latest and (latest.expires_at - now) > grace_seconds:
                    return latest.access_token

                refreshed_token = self._refresh_tokens(
                    binding_id=binding_id,
                    product=product,
                    instance_id=instance_id,
                    token_record=rec,
                    clock=clock,
                )
                return refreshed_token
        except TimeoutError:
            # A concurrent refresh is in-flight. Advise caller to retry.
            raise NeedsReauthError(
                auth_txn_id=f"refresh-in-flight-{binding_id}",
                product=product,
                message="Token refresh in progress; retry soon.",
            ) from None

    # ---------------- internal helpers --------------------------------- #
    def _refresh_tokens(
        self,
        *,
        binding_id: str,
        product: Product,
        instance_id: str,
        token_record: TokenRecord,
        clock: Clock,
    ) -> str:
        """Refresh the OAuth access token and persist the updated record."""
        client_id = _CLIENT_IDS[product]
        client_secret = _CLIENT_SECRETS[product]
        redirect_uri = _REDIRECT_URIS[product]
        scope = _SCOPE_DEFAULTS[product]

        instance_type = "cloud" if token_record.cloud_id else "datacenter"

        oauth_cfg = OAuthConfig(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            scope=scope,
            access_token=token_record.access_token,
            refresh_token=token_record.refresh_token,
            expires_at=token_record.expires_at,
            cloud_id=token_record.cloud_id,
            instance_type=instance_type,
            instance_url=token_record.instance_url,
        )

        if not oauth_cfg.refresh_access_token():
            raise NeedsReauthError(
                auth_txn_id=f"refresh-failed-{binding_id}",
                product=product,
                message="Failed to refresh OAuth token",
            )

        new_rec = TokenRecord(
            access_token=oauth_cfg.access_token or "",
            refresh_token=oauth_cfg.refresh_token,
            obtained_at=int(clock()),
            expires_at=int(oauth_cfg.expires_at or 0),
            cloud_id=oauth_cfg.cloud_id,
            instance_url=oauth_cfg.instance_url,
        )

        # Persist while still holding the lock
        self.store.save_tokens(binding_id, product, instance_id, new_rec)

        _LOG.info(
            "Refreshed %s access token for binding_id=%s**** (expires in %ss)",
            product,
            binding_id[:6],
            new_rec.ttl,
        )
        return new_rec.access_token
