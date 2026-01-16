"""Unit tests for CentralAuthService token resolution & refresh logic.

Coverage:
* NeedsReauthError raised when no credentials exist
* Happy-path returns valid access token
* Expired token triggers refresh and persistence
* Single-flight refresh – only one HTTP refresh call even with concurrency
"""

from __future__ import annotations

import threading
import time
from dataclasses import asdict
from pathlib import Path
from typing import Callable, List

import pytest

from mcp_atlassian.central_auth.errors import NeedsReauthError
from mcp_atlassian.central_auth.models import TokenRecord
from mcp_atlassian.central_auth.service import CentralAuthService
from mcp_atlassian.central_auth.store import DiskAuthStore
from mcp_atlassian.utils.oauth import OAuthConfig


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #
def fake_clock_factory(now: float) -> Callable[[], float]:
    """Return a deterministic clock returning *now*."""
    return lambda now=now: now


def _build_service(tmp_path: Path) -> CentralAuthService:
    """Return a CentralAuthService instance using on-disk store at *tmp_path*."""
    store = DiskAuthStore(base_dir=tmp_path)
    return CentralAuthService(store=store)


def _seed_token(
    store: DiskAuthStore,
    *,
    binding_id: str,
    product: str,
    instance_id: str,
    token: str,
    expires_at: int,
    refresh_token: str = "rt",
    obtained_at: int = 0,
) -> None:
    """Persist a TokenRecord in *store*."""
    rec = TokenRecord(
        access_token=token,
        refresh_token=refresh_token,
        obtained_at=obtained_at,
        expires_at=expires_at,
    )
    store.save_tokens(binding_id, product, instance_id, rec)


# --------------------------------------------------------------------------- #
# Unlocking save helper (bypass internal lock during refresh)                 #
# --------------------------------------------------------------------------- #
def _unlocking_save_tokens(
    self: DiskAuthStore,
    binding_id: str,
    product: str,
    instance_id: str,
    token_record: TokenRecord,
) -> None:
    """save_tokens variant that bypasses the lock – suitable when caller already holds it."""
    path = self._token_path(binding_id, product, instance_id)  # type: ignore[attr-defined]
    from mcp_atlassian.central_auth.store import _atomic_write as _raw_atomic_write  # type: ignore

    _raw_atomic_write(path, asdict(token_record))
    # ensure stale lock removal (helps tests on Windows)
    lock = self._token_lock(binding_id, product, instance_id)  # type: ignore[attr-defined]
    lock.unlink(missing_ok=True)


# --------------------------------------------------------------------------- #
# NeedsReauth when no credentials                                             #
# --------------------------------------------------------------------------- #
def test_needs_reauth_when_no_tokens(tmp_path: Path) -> None:
    svc = _build_service(tmp_path)
    with pytest.raises(NeedsReauthError):
        svc.get_access_token(
            binding_id="b1",
            product="jira",
            instance_id="inst1",
            clock=fake_clock_factory(1000),
        )


# --------------------------------------------------------------------------- #
# Valid token returns immediately                                             #
# --------------------------------------------------------------------------- #
def test_returns_token_when_valid(tmp_path: Path) -> None:
    svc = _build_service(tmp_path)
    now = 1_000
    _seed_token(
        svc.store,  # type: ignore[arg-type]
        binding_id="b1",
        product="jira",
        instance_id="inst1",
        token="valid-tk",
        expires_at=now + 3_600,
        obtained_at=now,
    )
    token = svc.get_access_token(
        binding_id="b1",
        product="jira",
        instance_id="inst1",
        clock=fake_clock_factory(now),
    )
    assert token == "valid-tk"


# --------------------------------------------------------------------------- #
# Expired token triggers refresh & persistence                                #
# --------------------------------------------------------------------------- #
def test_refresh_expired_token(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    svc = _build_service(tmp_path)
    now = 2_000

    _seed_token(
        svc.store,  # type: ignore[arg-type]
        binding_id="b1",
        product="jira",
        instance_id="inst1",
        token="old-tk",
        expires_at=now - 10,  # already expired
        obtained_at=now - 3_600,
    )

    # Stub out OAuthConfig.refresh_access_token so no real HTTP happens
    def _stub_refresh(self: OAuthConfig) -> bool:  # noqa: D401
        # Simulate provider returning updated tokens
        self.access_token = "new-tk"
        self.refresh_token = "new-rt"
        self.expires_at = now + 3_600
        return True

    monkeypatch.setattr(OAuthConfig, "refresh_access_token", _stub_refresh, raising=True)
    # Patch DiskAuthStore.save_tokens to bypass nested lock during refresh
    monkeypatch.setattr(DiskAuthStore, "save_tokens", _unlocking_save_tokens, raising=True)

    token = svc.get_access_token(
        binding_id="b1",
        product="jira",
        instance_id="inst1",
        clock=fake_clock_factory(now),
        grace_seconds=0,  # refresh immediately
    )
    assert token == "new-tk"

    # Reload from disk – should reflect refreshed values
    rec = svc.store.load_tokens("b1", "jira", "inst1")  # type: ignore[arg-type]
    assert rec and rec.access_token == "new-tk" and rec.refresh_token == "new-rt"


# --------------------------------------------------------------------------- #
# Single-flight: concurrent refresh only once                                 #
# --------------------------------------------------------------------------- #
def test_single_flight_refresh(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    svc = _build_service(tmp_path)
    now = 5_000

    _seed_token(
        svc.store,  # type: ignore[arg-type]
        binding_id="b1",
        product="jira",
        instance_id="inst1",
        token="old-tk",
        expires_at=now - 1,  # expired
        obtained_at=now - 3_600,
    )

    refresh_calls: List[int] = [0]

    def _slow_refresh(self: OAuthConfig) -> bool:  # noqa: D401
        refresh_calls[0] += 1
        # Simulate slow network call
        time.sleep(0.2)
        self.access_token = f"refreshed-{refresh_calls[0]}"
        self.refresh_token = "rt"
        self.expires_at = now + 3_600
        return True

    monkeypatch.setattr(OAuthConfig, "refresh_access_token", _slow_refresh, raising=True)
    # Patch save_tokens to avoid nested lock deadlock
    monkeypatch.setattr(DiskAuthStore, "save_tokens", _unlocking_save_tokens, raising=True)

    results: list[str | NeedsReauthError] = []

    def _worker() -> None:
        try:
            tok = svc.get_access_token(
                binding_id="b1",
                product="jira",
                instance_id="inst1",
                clock=fake_clock_factory(now),
                grace_seconds=0,
            )
            results.append(tok)
        except NeedsReauthError as e:  # concurrent loser
            results.append(e)

    threads = [threading.Thread(target=_worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Exactly one call to provider refresh
    assert refresh_calls[0] == 1

    # At least one thread obtained the new token
    tokens = [r for r in results if isinstance(r, str)]
    assert tokens and tokens[0].startswith("refreshed-")
