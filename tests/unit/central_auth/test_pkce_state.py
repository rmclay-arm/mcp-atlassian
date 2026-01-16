"""
Unit tests for PKCE helpers and state (CSRF) helpers.


These tests are CI-safe (no network), cover:
* Code-verifier / S256 challenge generation
* State build / parse happy-path
* Signature tamper detection
"""

from __future__ import annotations

import base64
import re
from hashlib import sha256

import pytest

from mcp_atlassian.central_auth.pkce import generate_code_verifier, code_challenge_s256
from mcp_atlassian.central_auth.state import build_state, parse_state, InvalidStateError


ALLOWED_CHARS_RE = re.compile(r"^[A-Za-z0-9\-._~]+$")  # RFC-7636


# --------------------------------------------------------------------------- #
# PKCE                                                                        #
# --------------------------------------------------------------------------- #
def test_generate_code_verifier_default_length() -> None:
    verifier = generate_code_verifier()
    assert 43 <= len(verifier) <= 128
    assert ALLOWED_CHARS_RE.match(verifier), "Verifier contains non-RFC chars"


def test_generate_code_verifier_custom_length() -> None:
    v = generate_code_verifier(50)
    assert len(v) == 50


def test_generate_code_verifier_invalid_len() -> None:
    with pytest.raises(ValueError):
        _ = generate_code_verifier(20)  # below minimum
    with pytest.raises(ValueError):
        _ = generate_code_verifier(200)  # above maximum


def test_code_challenge_s256_matches_reference() -> None:
    verifier = "test_verifier_1234567890"
    digest = sha256(verifier.encode("ascii")).digest()
    expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    assert code_challenge_s256(verifier) == expected


# --------------------------------------------------------------------------- #
# STATE BUILD / PARSE                                                         #
# --------------------------------------------------------------------------- #
def fake_clock() -> float:  # frozen at 2023-01-01T00:00:00Z
    return 1_672_531_200.0


def test_state_round_trip() -> None:
    auth_txn_id = "123e4567-e89b-12d3-a456-426614174000"
    secret = "super-secret"
    state = build_state(auth_txn_id, secret, clock=fake_clock)
    parsed_txn_id, ts = parse_state(state, secret)
    assert parsed_txn_id == auth_txn_id
    assert ts == int(fake_clock())


def test_state_tamper_detection() -> None:
    auth_txn_id = "123e4567-e89b-12d3-a456-426614174000"
    secret = "super-secret"
    raw_state = build_state(auth_txn_id, secret, clock=fake_clock)

    # Modify one char in the signature (end of the string after base64 decode)
    tampered = list(raw_state)
    tampered[-1] = "A" if tampered[-1] != "A" else "B"
    tampered_state = "".join(tampered)

    with pytest.raises(InvalidStateError):
        parse_state(tampered_state, secret)
