"""Verify OAuth transaction records persist binding_id and tokens saved accordingly."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_atlassian.central_auth.models import TokenRecord
from mcp_atlassian.central_auth.service import CentralAuthService
from mcp_atlassian.central_auth.store import DiskAuthStore, binding_id_from_link_code


@pytest.fixture()
def store(tmp_path: Path) -> DiskAuthStore:
    """Return a temporary DiskAuthStore instance rooted at *tmp_path*."""
    return DiskAuthStore(base_dir=tmp_path)


def test_txn_persists_binding_id_and_token_storage(store: DiskAuthStore) -> None:
    """End-to-end check:

    1. build_authorize_url() with link_code -> txn stored with binding_id
    2. exchange_code() stores tokens under same binding_id / instance_id
    """
    svc = CentralAuthService(store=store)

    link_code = "CCCCCCCCCCCCCCCC"
    binding_id = binding_id_from_link_code(link_code)
    instance_id = "default"
    redirect_uri = "https://example.com/callback"

    # Configure dummy environment for authorize URL construction
    from mcp_atlassian.central_auth import service as _svc_mod

    _svc_mod._AUTH_URLS["jira"] = "https://auth.example.com/authorize"
    _svc_mod._CLIENT_IDS["jira"] = "dummy-client-id"

    # Kick off flow (creates txn)
    authorize_url = svc.build_authorize_url(
        product="jira",
        instance_id=instance_id,
        redirect_uri=redirect_uri,
        link_code=link_code,
    )
    # One txn JSON should be created under store.base_dir/txns
    txns = list((store.base_dir / "txns").glob("*.json"))
    assert len(txns) == 1, "Exactly one auth transaction file expected"
    auth_txn_id = txns[0].stem
    txn = store.get_auth_txn(auth_txn_id)
    assert txn is not None
    assert txn.binding_id == binding_id

    # Extract state from the authorize URL (used by exchange_code)
    from urllib.parse import parse_qs, urlparse

    state = parse_qs(urlparse(authorize_url).query)["state"][0]

    # Prepare mock HTTP post to avoid real network
    from types import SimpleNamespace
    import requests as _real_requests
    captured: dict[str, object] = {}

    def fake_post(url: str, *, data: dict, timeout: tuple[int, int]) -> object:  # noqa: ANN001
        captured["url"] = url
        captured["data"] = data
        resp = SimpleNamespace()
        resp.ok = True
        resp.status_code = 200
        resp.text = "{}"
        resp.json = lambda: {
            "access_token": "demo-access",
            "refresh_token": "demo-refresh",
            "expires_in": 3600,
        }
        return resp

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(_real_requests, "post", fake_post, raising=True)

    # Simulate provider callback: exchange_code() stores tokens
    svc.exchange_code(product="jira", code="dummy", state=state)
    monkeypatch.undo()

    tok = store.load_tokens(binding_id, "jira", instance_id)
    assert tok is not None
    assert isinstance(tok, TokenRecord)
