"""PKCE (Proof Key for Code Exchange) helpers.

RFC 7636 defines PKCE to protect public OAuth clients.  The mechanism relies on
a *code verifier* (random high-entropy string) generated at the beginning of
the flow and a *code challenge* derived from that verifier that is sent to the
authorization endpoint.

Only the S256 transformation is implemented because Atlassian’s OAuth 2.0
implementation (and virtually every modern provider) requires it.

This module intentionally performs **no logging** of verifiers or challenges.
"""

from __future__ import annotations

import base64
import os
import secrets
from hashlib import sha256
from typing import Final

# RFC-7636 §4.1 mandates the verifier length between 43 and 128 characters.
_VERIFIER_LEN: Final[int] = 64
_ALLOWED_CHARS: Final[str] = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    "-._~"
)


def _random_urlsafe_string(length: int) -> str:
    """Return a cryptographically secure, URL-safe random string."""
    return "".join(secrets.choice(_ALLOWED_CHARS) for _ in range(length))


def generate_code_verifier(length: int = _VERIFIER_LEN) -> str:
    """Generate a high-entropy code verifier.

    Parameters
    ----------
    length:
        Desired length between 43 and 128 characters (default 64).

    Returns
    -------
    str
        The generated code verifier.
    """
    if not 43 <= length <= 128:
        raise ValueError("code verifier length must be 43-128 characters")
    return _random_urlsafe_string(length)


def code_challenge_s256(verifier: str) -> str:
    """Compute the *S256* PKCE code challenge for a given verifier.

    Parameters
    ----------
    verifier:
        The code verifier string.

    Returns
    -------
    str
        Base64url-encoded SHA-256 hash without padding.
    """
    digest = sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
