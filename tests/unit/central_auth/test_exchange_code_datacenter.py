"""Tests for CentralAuthService.exchange_code real token exchange (Data Center)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest

from mcp_atlassian.central_auth.service import CentralAuthService
from mcp_atlassian.central_auth.store import DiskAuthStore


@pytest.fixture()
def store(tmp_path: Path) -> DiskAuthStore:
    """Return a temporary DiskAuthStore instance rooted at *tmp_path*."""
    return DiskAuthStore(base_dir=tmp_path)


def test_exchange_code_posts_to_token_endpoint(store: DiskAuthStore, monkeypatch) -> None:
    """Ensure CentralAuthService exchanges the code against /token endpoint with PKCE."""
    svc = CentralAuthService(store=store)

    # Configure fake environment for Jira DC OAuth
    from mcp_atlassian.central_auth import service as _svc_mod

    base_authorize = "https://jira.example.test/rest/oauth2/latest/authorize"
    _svc_mod._AUTH_URLS["jira"] = base_authorize
    _svc_mod._CLIENT_IDS["jira"] = "dummy-client-id"
    _svc_mod._CLIENT_SECRETS["jira"] = "dummy-secret"

    instance_id = "my-dc"
    redirect_uri = "https://example.com/callback"

    # Step 1: kick off authorize URL (creates txn + PKCE code_verifier)
    authorize_url = svc.build_authorize_url(
        product="jira",
        instance_id=instance_id,
        redirect_uri=redirect_uri,
    )

    # Extract auth_txn_id & state
    txns = list((store.base_dir / "txns").glob("*.json"))
    assert len(txns) == 1
    auth_txn_id = txns[0].stem
    txn = store.get_auth_txn(auth_txn_id)
    assert txn is not None
    state = parse_qs(urlparse(authorize_url).query)["state"][0]

    # Prepare mock for requests.post
    captured: dict[str, object] = {}

    def fake_post(url: str, *, data: dict, timeout: tuple[int, int]) -> object:  # noqa: ANN001
        captured["url"] = url
        captured["data"] = data
        # Minimal dummy OK response
        resp = SimpleNamespace()
        resp.ok = True
        resp.status_code = 200
        resp.text = "{}"
        resp.json = lambda: {
            "access_token": "access-xyz",
            "refresh_token": "refresh-xyz",
            "expires_in": 3600,
        }
        return resp

    import requests as _real_requests

    monkeypatch.setattr(_real_requests, "post", fake_post, raising=True)

    # Step 2: simulate callback -> exchange code
    svc.exchange_code(product="jira", code="dummy-code", state=state)

    # Assertions on captured HTTP request
    assert captured["url"] == "https://jira.example.test/rest/oauth2/latest/token"
    from typing import Any, Dict, cast

    body = cast(Dict[str, Any], captured["data"])
    assert body["code"] == "dummy-code"
    assert body["redirect_uri"] == redirect_uri
    assert body["code_verifier"] == txn.code_verifier

    # Tokens persisted
    tok = store.load_tokens("default", "jira", instance_id)
    assert tok is not None
    assert tok.access_token == "access-xyz"
