"""State parameter helpers for the OAuth 2.0 web-flow.

The *state* parameter protects the user against CSRF and *open redirect*
attacks.  MCP-Atlassian encodes three values in a compact, URL-safe string:

1. ``auth_txn_id`` – UUID generated at the beginning of the flow
2. ``ts`` – UNIX timestamp produced by an injected :pyclass:`~mcp_atlassian.central_auth.clock.Clock`
3. ``sig`` – HMAC-SHA256 signature of the first two fields using an application
   secret

Format (plain text before base64-url encoding)::

    <auth_txn_id>:<ts>:<sig>

The encoded value contains **no delimiters that could be interpreted as
a path or query separator**, preventing open-redirect tricks such as abusing
``state`` to smuggle a second ``?`` in the callback URL.

Logging
-------
Only the (truncated) ``auth_txn_id`` is ever logged; the full state string as
well as the HMAC secret are *never* written to logs.
"""

from __future__ import annotations

import base64
import hmac
import logging
import binascii
from hashlib import sha256
from typing import Final

from mcp_atlassian.central_auth.clock import Clock, default_clock

_LOG = logging.getLogger("mcp-atlassian.central_auth.state")

_SIG_LEN: Final[int] = 12  # characters kept from hex digest


def _b64e(data: str) -> str:
    """Base64-URL encode *without* padding."""
    return base64.urlsafe_b64encode(data.encode("utf-8")).rstrip(b"=").decode("ascii")


def _b64d(data: str) -> str:
    """Decode base64-URL data that may lack padding."""
    pad_len = (-len(data)) % 4
    return base64.urlsafe_b64decode(data + "=" * pad_len).decode("utf-8")


def _sign(message: str, secret: str) -> str:
    digest = hmac.new(secret.encode(), msg=message.encode(), digestmod=sha256).hexdigest()
    return digest[:_SIG_LEN]


def build_state(auth_txn_id: str, secret: str, *, clock: Clock = default_clock) -> str:
    """Build the state string for an OAuth authorization request.

    Parameters
    ----------
    auth_txn_id:
        Unique identifier for the OAuth transaction (e.g. UUID4).
    secret:
        Application secret used to sign the state.
    clock:
        Time source; defaults to :pyfunc:`~mcp_atlassian.central_auth.clock.default_clock`.

    Returns
    -------
    str
        URL-safe state value.
    """
    ts = int(clock())
    payload = f"{auth_txn_id}:{ts}"
    sig = _sign(payload, secret)
    state_raw = f"{payload}:{sig}"
    encoded = _b64e(state_raw)
    _LOG.debug("Built state for auth_txn_id=%s****", auth_txn_id[:6])
    return encoded


class InvalidStateError(Exception):
    """Raised when an incoming state is missing/invalid or signature check fails."""


def parse_state(state: str, secret: str) -> tuple[str, int]:
    """Validate and decode a state received in the OAuth callback.

    Parameters
    ----------
    state:
        The base64-url encoded state string from the callback request.
    secret:
        Application secret (same value used in :pyfunc:`build_state`).

    Returns
    -------
    Tuple[str, int]
        ``(auth_txn_id, ts)`` on success.

    Raises
    ------
    InvalidStateError
        If the state is malformed or the signature does not validate.
    """
    try:
        decoded = _b64d(state)
        parts = decoded.split(":")
        if len(parts) != 3:
            raise InvalidStateError("state has an unexpected format")

        auth_txn_id, ts_str, sig = parts
        if not auth_txn_id or not ts_str.isdigit():
            raise InvalidStateError("state missing fields")

        expected_sig = _sign(f"{auth_txn_id}:{ts_str}", secret)
        if not hmac.compare_digest(sig, expected_sig):
            raise InvalidStateError("state signature mismatch")

        _LOG.debug("Parsed state for auth_txn_id=%s****", auth_txn_id[:6])
        return auth_txn_id, int(ts_str)
    except (ValueError, binascii.Error):  # noqa: B902  # binascii imported implicitly by b64
        raise InvalidStateError("state cannot be decoded") from None
