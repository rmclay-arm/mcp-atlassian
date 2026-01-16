"""
Unit tests for DiskAuthStore and auth-transaction TTL logic.

Coverage:
* AuthTxnRecord.is_expired correctness with fake clock
* DiskAuthStore atomic write + idempotent consume_auth_txn
* DiskAuthStore file-lock/lease exclusivity (single holder)
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Callable

import pytest

from mcp_atlassian.central_auth.models import AuthTxnRecord, TokenRecord
from mcp_atlassian.central_auth.store import DiskAuthStore


# --------------------------------------------------------------------------- #
# helpers                                                                     #
# --------------------------------------------------------------------------- #
def fake_clock_factory(now: float) -> Callable[[], float]:
    """Return a callable clock that always returns *now*."""
    return lambda now=now: now


# --------------------------------------------------------------------------- #
# TTL expiry behaviour                                                        #
# --------------------------------------------------------------------------- #
def test_auth_txn_ttl_expiry_with_fake_clock() -> None:
    record = AuthTxnRecord(
        auth_txn_id="tx1",
        client_id="cid",
        redirect_uri="https://example.com/cb",
        product="jira",
        code_verifier="v",
        code_challenge="c",
        created_at=1000,
        ttl_seconds=60,
    )
    assert record.is_expired(clock=fake_clock_factory(1059)) is False
    assert record.is_expired(clock=fake_clock_factory(1061)) is True


# --------------------------------------------------------------------------- #
# DiskAuthStore atomic write & idempotent consume                             #
# --------------------------------------------------------------------------- #
def _build_store(tmp_path: Path) -> DiskAuthStore:
    return DiskAuthStore(base_dir=tmp_path)


def test_disk_store_atomic_write_and_consume(tmp_path: Path) -> None:
    store = _build_store(tmp_path)

    rec = AuthTxnRecord(
        auth_txn_id="txn123",
        client_id="cid",
        redirect_uri="https://example.com/cb",
        product="jira",
        code_verifier="ver",
        code_challenge="chal",
    )

    # create_auth_txn performs atomic write
    store.create_auth_txn(rec)

    src_path = tmp_path / "txns" / "txn123.json"
    assert src_path.exists()
    # No lingering *.tmp file
    assert not list(src_path.parent.glob("*.tmp"))

    # First consume succeeds & moves file
    first = store.consume_auth_txn("txn123", state_secret="dummy")
    assert first == rec

    # Source file is gone, destination exists
    consumed_path = tmp_path / "txns" / "consumed" / "txn123.json"
    assert consumed_path.exists() and not src_path.exists()

    # Second consume returns None (already consumed)
    assert store.consume_auth_txn("txn123", state_secret="dummy") is None


# --------------------------------------------------------------------------- #
# File-lock / lease exclusivity                                               #
# --------------------------------------------------------------------------- #
def test_token_lock_single_holder(tmp_path: Path) -> None:
    store = _build_store(tmp_path)
    bind, prod, inst = "bind1", "jira", "inst1"
    tok = TokenRecord(
        access_token="at",
        expires_at=1300,
        obtained_at=1000,
        refresh_token="rt",
    )

    # Acquire the lock in a background thread and hold it briefly
    lock_path = store._token_lock(bind, prod, inst)  # type: ignore[attr-defined]

    def holder() -> None:
        # Use the same internal helper to obtain lock
        from mcp_atlassian.central_auth.store import _file_lock

        with _file_lock(lock_path, retries=0, delay=0):  # immediate hold
            time.sleep(0.3)

    t = threading.Thread(target=holder)
    t.start()
    time.sleep(0.05)  # ensure thread grabbed lock

    # Attempting to save tokens while lock held should raise TimeoutError
    with pytest.raises(TimeoutError):
        store.save_tokens(bind, prod, inst, tok)

    t.join()

    # After releasing the lock, save_tokens succeeds
    store.save_tokens(bind, prod, inst, tok)
    saved_path = store._token_path(bind, prod, inst)  # type: ignore[attr-defined]
    with saved_path.open() as fh:
        data = json.load(fh)
    assert data["access_token"] == "at"
