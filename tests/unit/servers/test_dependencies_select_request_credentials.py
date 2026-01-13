"""Unit tests for `_select_request_credentials` helper.

These tests lock in the *presence-based* credential selection semantics
for Jira and Confluence without exercising the higher-level fetcher
dependencies.
"""

from types import SimpleNamespace
from typing import Literal, Tuple

import pytest

from mcp_atlassian.servers.dependencies import _select_request_credentials


class DummyRequest:  # Minimal stand-in for starlette.requests.Request
    """Simple request stub exposing a mutable ``state`` attribute."""

    def __init__(self) -> None:
        self.state = SimpleNamespace()


Returned = Tuple[str | None, object | None, object | None, object | None]


def _call(
    request: DummyRequest, service: Literal["jira", "confluence"]
) -> Returned:  # pragma: no cover – alias for brevity
    return _select_request_credentials(request, service)


# ---------------------------------------------------------------------------
# 1) Per-product keys present → per-product values win (even if falsy)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("empty_value", ["", None])
def test_jira_per_product_keys_override_legacy(empty_value: object) -> None:
    req = DummyRequest()
    # Per-product keys set (some intentionally falsy)
    req.state.user_jira_auth_type = empty_value
    req.state.user_jira_token = empty_value
    req.state.user_jira_cloud_id = empty_value
    req.state.user_jira_email = empty_value

    # Legacy keys should *not* be returned
    req.state.user_atlassian_auth_type = "legacy"
    req.state.user_atlassian_token = "legacy-token"
    req.state.user_atlassian_cloud_id = "legacy-cloud-id"
    req.state.user_atlassian_email = "legacy@example.com"

    assert _call(req, "jira") == (
        empty_value,
        empty_value,
        empty_value,
        empty_value,
    )


@pytest.mark.parametrize("empty_value", ["", None])
def test_confluence_per_product_keys_override_legacy(empty_value: object) -> None:
    req = DummyRequest()
    req.state.user_confluence_auth_type = empty_value
    req.state.user_confluence_token = empty_value
    req.state.user_confluence_cloud_id = empty_value
    req.state.user_confluence_email = empty_value

    req.state.user_atlassian_auth_type = "legacy"
    req.state.user_atlassian_token = "legacy-token"
    req.state.user_atlassian_cloud_id = "legacy-cloud-id"
    req.state.user_atlassian_email = "legacy@example.com"

    assert _call(req, "confluence") == (
        empty_value,
        empty_value,
        empty_value,
        empty_value,
    )


# ---------------------------------------------------------------------------
# 3) No per-product keys at all → legacy values are used
# ---------------------------------------------------------------------------


def test_selector_falls_back_to_legacy_when_per_product_absent() -> None:
    req = DummyRequest()
    # Only legacy attributes defined
    req.state.user_atlassian_auth_type = "pat"
    req.state.user_atlassian_token = "t123"
    req.state.user_atlassian_cloud_id = "c123"
    req.state.user_atlassian_email = "user@example.com"

    expected: Returned = (
        "pat",
        "t123",
        "c123",
        "user@example.com",
    )
    assert _call(req, "jira") == expected
    assert _call(req, "confluence") == expected


# ---------------------------------------------------------------------------
# 4) Both per-product and legacy exist → per-product wins *for that service*
# ---------------------------------------------------------------------------


def test_per_product_wins_over_legacy_when_both_present() -> None:
    req = DummyRequest()

    # Jira: both present
    req.state.user_jira_auth_type = "oauth"
    req.state.user_jira_token = "jira-token"
    req.state.user_jira_cloud_id = "jira-cloud"
    req.state.user_jira_email = "jira@example.com"

    # Confluence: both present
    req.state.user_confluence_auth_type = "pat"
    req.state.user_confluence_token = "conf-token"
    req.state.user_confluence_cloud_id = "conf-cloud"
    req.state.user_confluence_email = "conf@example.com"

    # Legacy fallbacks
    req.state.user_atlassian_auth_type = "legacy"
    req.state.user_atlassian_token = "legacy-token"
    req.state.user_atlassian_cloud_id = "legacy-cloud-id"
    req.state.user_atlassian_email = "legacy@example.com"

    assert _call(req, "jira") == (
        "oauth",
        "jira-token",
        "jira-cloud",
        "jira@example.com",
    )
    assert _call(req, "confluence") == (
        "pat",
        "conf-token",
        "conf-cloud",
        "conf@example.com",
    )
