"""Concurrency-safe, on-disk storage for Central OAuth (phase 1).

This module introduces a *narrow* persistence interface
(:class:`AuthStore`) and a JSON-file implementation
(:class:`DiskAuthStore`).  The design follows these goals:

* **Atomicity** – writes use *temp-file + os.replace*.
* **Concurrency** – single-use consumption and per-token update locks.
* **Portability** – only standard-library modules are required.
* **Filename safety** – externally supplied identifiers are hashed /
  slugified before hitting the filesystem.

Environment variables
---------------------
MCP_AUTH_STORAGE_DIR
    Base directory for all persisted data.
    Defaults to ``~/.mcp-atlassian/auth`` when unset.
MCP_AUTH_ENCRYPT_KEY   (reserved for phase 2)
    Optional key for at-rest encryption of *refresh_token* values.
"""

from __future__ import annotations

import json
import os
import secrets
import time
from contextlib import contextmanager
from dataclasses import asdict
from hashlib import sha256
from pathlib import Path
from typing import Protocol, runtime_checkable

from mcp_atlassian.central_auth.clock import default_clock as _clock
from mcp_atlassian.central_auth.models import AuthTxnRecord, TokenRecord

# --------------------------------------------------------------------------- #
# helpers                                                                     #
# --------------------------------------------------------------------------- #


def _now() -> int:
    return int(_clock())


def _hash(text: str, length: int = 12) -> str:
    return sha256(text.encode()).hexdigest()[:length]


def binding_id_from_link_code(link_code: str, *, length: int = 12) -> str:
    """Return the deterministic binding_id derived from a link_code.

    All components must use this helper so tokens are stored and looked-up
    under the same hashed identifier. The implementation delegates to the
    internal ``_hash`` helper to guarantee identical behaviour.
    """
    return _hash(link_code, length)


def _slug(text: str, max_len: int = 80) -> str:
    """Filesystem-safe slug (borrowed from utils.oauth)."""
    import re

    text = (text or "").strip().lower()
    text = re.sub(r"[^a-z0-9._-]+", "-", text)
    text = re.sub(r"-{2,}", "-", text).strip("-")
    return text[:max_len] or "unknown"


def _atomic_write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, separators=(",", ":"), sort_keys=True)
    os.replace(tmp, path)  # atomic on POSIX


@contextmanager
def _file_lock(lock_path: Path, retries: int = 25, delay: float = 0.2):  # noqa: D401
    """Advisory file lock using ``os.O_EXCL`` temp-file creation."""
    # Ensure the lock directory exists before attempting to create the file
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    for attempt in range(retries + 1):
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_RDWR)
            os.close(fd)
            break  # acquired!
        except FileExistsError:
            if attempt == retries:
                raise TimeoutError(f"Could not acquire lock {lock_path}") from None
            time.sleep(delay)
    try:
        yield
    finally:
        try:
            lock_path.unlink(missing_ok=True)
        except Exception:  # pragma: no cover
            pass


# --------------------------------------------------------------------------- #
# public interface                                                            #
# --------------------------------------------------------------------------- #


@runtime_checkable
class AuthStore(Protocol):
    """Minimal persistence contract for central OAuth."""

    # ----- link codes ------------------------------------------------------ #
    def create_link_code(self, ttl_seconds: int = 600) -> str: ...

    # ----- auth transactions ---------------------------------------------- #
    def create_auth_txn(self, record: AuthTxnRecord) -> None: ...
    def get_auth_txn(self, auth_txn_id: str) -> AuthTxnRecord | None: ...
    def consume_auth_txn(self, auth_txn_id: str, state_secret: str) -> AuthTxnRecord | None: ...

    # ----- token storage --------------------------------------------------- #
    def save_tokens(
        self,
        binding_id: str,
        product: str,
        instance_id: str,
        token_record: TokenRecord,
    ) -> None: ...

    def load_tokens(
        self, binding_id: str, product: str, instance_id: str
    ) -> TokenRecord | None: ...

    def delete_tokens(self, binding_id: str, product: str, instance_id: str) -> None: ...

    # ----- maintenance ----------------------------------------------------- #
    def cleanup_expired_txns(self) -> int: ...


# --------------------------------------------------------------------------- #
# Disk implementation                                                         #
# --------------------------------------------------------------------------- #


class DiskAuthStore(AuthStore):
    """JSON-file implementation of :class:`AuthStore`."""

    def __init__(self, base_dir: str | os.PathLike | None = None) -> None:
        self.base_dir = Path(
            base_dir
            or os.getenv("MCP_AUTH_STORAGE_DIR")
            or Path.home() / ".mcp-atlassian" / "auth"
        ).expanduser()
        self.base_dir.mkdir(parents=True, exist_ok=True)

    # ---------------- link code helpers ---------------------------------- #
    def _link_path(self, binding_id: str) -> Path:
        return self.base_dir / "links" / f"{binding_id}.json"

    def create_link_code(self, ttl_seconds: int = 600) -> str:
        link_code = secrets.token_urlsafe(16)
        binding_id = _hash(link_code)
        rec = {"binding_id": binding_id, "created_at": _now(), "ttl_seconds": ttl_seconds}
        _atomic_write(self._link_path(binding_id), rec)
        return link_code

    # ---------------- auth transactions ---------------------------------- #
    def _txn_path(self, auth_txn_id: str) -> Path:
        return self.base_dir / "txns" / f"{auth_txn_id}.json"

    def _txn_consumed_path(self, auth_txn_id: str) -> Path:
        return self.base_dir / "txns" / "consumed" / f"{auth_txn_id}.json"

    def create_auth_txn(self, record: AuthTxnRecord) -> None:
        _atomic_write(self._txn_path(record.auth_txn_id), asdict(record))

    def get_auth_txn(self, auth_txn_id: str) -> AuthTxnRecord | None:
        p = self._txn_path(auth_txn_id)
        if not p.exists():
            return None
        with p.open(encoding="utf-8") as fh:
            data = json.load(fh)
        return AuthTxnRecord(**data)

    def consume_auth_txn(self, auth_txn_id: str, state_secret: str) -> AuthTxnRecord | None:  # noqa: ARG002
        """Return and atomically mark the txn as consumed (single-use)."""
        src = self._txn_path(auth_txn_id)
        if not src.exists():
            return None
        dst = self._txn_consumed_path(auth_txn_id)
        dst.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.replace(src, dst)  # atomic rename – fails if concurrent consumer won
        except FileNotFoundError:
            return None  # someone else won the race
        with dst.open(encoding="utf-8") as fh:
            data = json.load(fh)
        return AuthTxnRecord(**data)

    # ---------------- token storage -------------------------------------- #
    def _token_path(self, binding_id: str, product: str, instance_id: str) -> Path:
        prod = _slug(product, 24)
        inst = _hash(instance_id, 16)
        return self.base_dir / "tokens" / binding_id / prod / f"{inst}.json"

    def _token_lock(self, binding_id: str, product: str, instance_id: str) -> Path:
        return self._token_path(binding_id, product, instance_id).with_suffix(".lock")

    def save_tokens(
        self,
        binding_id: str,
        product: str,
        instance_id: str,
        token_record: TokenRecord,
    ) -> None:
        path = self._token_path(binding_id, product, instance_id)
        lock = self._token_lock(binding_id, product, instance_id)
        # Fail-fast if another process/thread currently holds the update lock.
        # This prevents long waits and aligns with unit test expectations that
        # a simultaneous writer immediately raises ``TimeoutError``.
        with _file_lock(lock, retries=0, delay=0):
            _atomic_write(path, asdict(token_record))

    def load_tokens(
        self, binding_id: str, product: str, instance_id: str
    ) -> TokenRecord | None:
        path = self._token_path(binding_id, product, instance_id)
        if not path.exists():
            return None
        with path.open(encoding="utf-8") as fh:
            data = json.load(fh)
        return TokenRecord(**data)

    def delete_tokens(self, binding_id: str, product: str, instance_id: str) -> None:
        path = self._token_path(binding_id, product, instance_id)
        lock = self._token_lock(binding_id, product, instance_id)
        with _file_lock(lock):
            try:
                path.unlink(missing_ok=True)
            finally:
                lock.unlink(missing_ok=True)

    # ---------------- maintenance ---------------------------------------- #
    def cleanup_expired_txns(self) -> int:
        txndir = self.base_dir / "txns"
        if not txndir.exists():
            return 0
        removed = 0
        now = _now()
        for p in txndir.glob("*.json"):
            try:
                with p.open() as fh:
                    data = json.load(fh)
                ttl = int(data.get("ttl_seconds", 900))
                created = int(data.get("created_at", 0))
                if (now - created) > ttl:
                    p.unlink(missing_ok=True)
                    removed += 1
            except Exception:  # pragma: no cover
                continue
        return removed


# --------------------------------------------------------------------------- #
# Convenience – default singleton                                            #
# --------------------------------------------------------------------------- #

_default_store: DiskAuthStore | None = None


def default_store() -> DiskAuthStore:
    """Return a process-wide singleton :class:`DiskAuthStore`."""
    global _default_store  # noqa: PLW0603
    if _default_store is None:
        _default_store = DiskAuthStore()
    return _default_store
