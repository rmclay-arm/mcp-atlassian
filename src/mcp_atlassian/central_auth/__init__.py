"""Central authentication core package.

This namespace hosts reusable, **HTTP-agnostic** building blocks for OAuth 2.0
web flows shared by Jira, Confluence and future Atlassian products.

Sub-modules
-----------
clock
    Test-friendly time abstraction.
pkce
    Proof-Key for Code Exchange helpers.
state
    CSRF-resistant ``state`` parameter encoding / validation.
models
    Immutable dataclasses capturing auth transaction & token metadata.
errors
    Exception types used by the central auth logic.
log_utils
    Structured logging helpers (thin wrapper around :pymod:`logging`).

All public objects are re-exported here for convenience.
"""

from __future__ import annotations

from .clock import Clock, default_clock  # noqa: F401
from .pkce import generate_code_verifier, code_challenge_s256  # noqa: F401
from .state import build_state, parse_state, InvalidStateError  # noqa: F401
from .models import AuthTxnRecord, TokenRecord  # noqa: F401
from .errors import NeedsReauthError  # noqa: F401
from .log_utils import get_auth_logger  # noqa: F401

__all__ = [
    # clock
    "Clock",
    "default_clock",
    # pkce
    "generate_code_verifier",
    "code_challenge_s256",
    # state
    "build_state",
    "parse_state",
    "InvalidStateError",
    # models
    "AuthTxnRecord",
    "TokenRecord",
    # errors
    "NeedsReauthError",
    # logging helpers
    "get_auth_logger",
]
