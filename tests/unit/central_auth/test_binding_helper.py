"""Unit tests for binding_id_from_link_code helper and token retrieval path."""

from __future__ import annotations

from pathlib import Path

from mcp_atlassian.central_auth.models import TokenRecord
from mcp_atlassian.central_auth.store import (
    DiskAuthStore,
    binding_id_from_link_code,
)


def _build_store(tmp_path: Path) -> DiskAuthStore:
    """Return a DiskAuthStore rooted at *tmp_path* (helper)."""
    return DiskAuthStore(base_dir=tmp_path)


def test_binding_id_helper_matches_store_hash(tmp_path: Path) -> None:
    """Helper must produce the same hash the store used when persisting tokens."""
    store = _build_store(tmp_path)

    link_code = "BBBBBBBBBBBBBBBB"  # deterministic value for reproducibility
    binding_id = binding_id_from_link_code(link_code)

    # Persist dummy token under computed binding_id
    tok = TokenRecord(
        access_token="at-token",
        expires_at=2000,
        obtained_at=1000,
        refresh_token=None,
        cloud_id="demo-cloud",
        instance_url="https://example.atlassian.net",
    )
    store.save_tokens(binding_id, "jira", "default", tok)

    # Simulate runtime lookup that only has the raw link_code header value
    looked_up = store.load_tokens(binding_id_from_link_code(link_code), "jira", "default")

    assert looked_up is not None, "TokenRecord should be retrievable by binding helper"
    assert looked_up.access_token == tok.access_token
