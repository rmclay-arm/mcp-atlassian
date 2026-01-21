"""Unit tests for /auth/{product}/start endpoint content negotiation."""

from __future__ import annotations

import urllib.parse
from unittest.mock import patch

import httpx
import pytest

from mcp_atlassian.servers.main import main_mcp

# --------------------------------------------------------------------------- #
# Constants                                                                   #
# --------------------------------------------------------------------------- #
REDIRECT_URI = "http://localhost/callback"
AUTHORIZE_URL = "https://jira.example.com/rest/oauth2/latest/authorize?foo=bar"
START_PATH = (
    "/auth/jira/start"
    f"?redirect_uri={urllib.parse.quote(REDIRECT_URI, safe='')}"
    "&instance=default"
)


# --------------------------------------------------------------------------- #
# Fixtures                                                                    #
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="session")
def asgi_app():
    """Return the Starlette application configured for tests."""
    return main_mcp.http_app(transport="sse")


@pytest.fixture(autouse=True)
def _patch_authorize_url():
    """Stub CentralAuthService.build_authorize_url to return a static URL."""
    with patch(
        "mcp_atlassian.servers.auth.CentralAuthService.build_authorize_url",
        return_value=AUTHORIZE_URL,
    ):
        yield


@pytest.fixture()
async def client(asgi_app):
    """Async HTTP client bound to the Starlette app."""
    transport = httpx.ASGITransport(app=asgi_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


# --------------------------------------------------------------------------- #
# Tests                                                                       #
# --------------------------------------------------------------------------- #
@pytest.mark.anyio
async def test_html_accept_redirect(client: httpx.AsyncClient):
    """Accept: text/html with no explicit format should trigger HTTP redirect."""
    resp = await client.get(START_PATH, headers={"Accept": "text/html"})
    assert resp.status_code == 303
    assert resp.headers["location"] == AUTHORIZE_URL
    # Body is expected to be empty for RedirectResponse
    assert resp.content in (b"", b"")  # tolerate implementation differences


@pytest.mark.anyio
async def test_json_accept_returns_json(client: httpx.AsyncClient):
    """Accept: application/json should return JSON with authorize_url."""
    resp = await client.get(START_PATH, headers={"Accept": "application/json"})
    assert resp.status_code == 200
    assert resp.json() == {"authorize_url": AUTHORIZE_URL}


@pytest.mark.anyio
async def test_format_json_forces_json(client: httpx.AsyncClient):
    """format=json query param forces JSON even if Accept prefers HTML."""
    resp = await client.get(
        START_PATH + "&format=json", headers={"Accept": "text/html"}
    )
    assert resp.status_code == 200
    assert resp.json() == {"authorize_url": AUTHORIZE_URL}


@pytest.mark.anyio
async def test_format_redirect_forces_redirect(client: httpx.AsyncClient):
    """format=redirect query param forces redirect even if Accept prefers JSON."""
    resp = await client.get(
        START_PATH + "&format=redirect",
        headers={"Accept": "application/json"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == AUTHORIZE_URL
