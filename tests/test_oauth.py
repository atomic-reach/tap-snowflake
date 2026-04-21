"""Unit tests for the tap_snowflake.oauth module."""

from __future__ import annotations

import datetime as dt
import json

import pytest
import responses

from tap_snowflake.oauth import (
    OAuthTokenRefreshError,
    SnowflakeOAuthRefreshAuthenticator,
    default_snowflake_token_endpoint,
)

TOKEN_ENDPOINT = "https://idp.example/oauth/token"


def _make_authenticator(
    *,
    refresh_token: str = "rt-test",
    client_id: str = "cid-test",
    client_secret: str = "csec-test",
    oauth_scopes: str | None = None,
    default_expiration: int = 600,
) -> SnowflakeOAuthRefreshAuthenticator:
    """Build an authenticator with default test values."""
    return SnowflakeOAuthRefreshAuthenticator(
        auth_endpoint=TOKEN_ENDPOINT,
        client_id=client_id,
        client_secret=client_secret,
        refresh_token=refresh_token,
        oauth_scopes=oauth_scopes,
        default_expiration=default_expiration,
    )


def test_oauth_request_body_shape() -> None:
    """Body carries the four expected fields; no scope by default."""
    auth = _make_authenticator()
    body = auth.oauth_request_body
    assert body == {
        "grant_type": "refresh_token",
        "refresh_token": "rt-test",
        "client_id": "cid-test",
        "client_secret": "csec-test",
    }
    assert "scope" not in body


def test_oauth_request_body_includes_scope() -> None:
    """Scope is included when configured."""
    auth = _make_authenticator(oauth_scopes="session:role:my_role")
    assert auth.oauth_request_body["scope"] == "session:role:my_role"


@responses.activate
def test_mint_posts_to_auth_endpoint_and_returns_token() -> None:
    """mint() POSTs to the endpoint and returns the access token."""
    responses.add(
        responses.POST,
        TOKEN_ENDPOINT,
        json={"access_token": "at-abc", "expires_in": 900},
        status=200,
    )
    auth = _make_authenticator()
    token = auth.mint()
    assert token == "at-abc"
    assert auth.expires_in == 900
    assert len(responses.calls) == 1
    posted = dict(
        item.split("=", 1) for item in responses.calls[0].request.body.split("&")
    )
    assert posted["grant_type"] == "refresh_token"
    assert posted["refresh_token"] == "rt-test"
    assert posted["client_id"] == "cid-test"
    assert posted["client_secret"] == "csec-test"


@responses.activate
def test_mint_memoized_when_token_valid() -> None:
    """Second call within expiry window short-circuits via is_token_valid."""
    responses.add(
        responses.POST,
        TOKEN_ENDPOINT,
        json={"access_token": "at-abc", "expires_in": 900},
        status=200,
    )
    auth = _make_authenticator()
    auth.mint()
    auth.mint()
    assert len(responses.calls) == 1


@responses.activate
def test_mint_refreshes_after_expiry() -> None:
    """Once last_refreshed is shifted past expiry, mint() re-posts."""
    responses.add(
        responses.POST,
        TOKEN_ENDPOINT,
        json={"access_token": "at-abc", "expires_in": 60},
        status=200,
    )
    auth = _make_authenticator()
    auth.mint()
    assert auth.last_refreshed is not None
    auth.last_refreshed -= dt.timedelta(seconds=auth.expires_in + 10)
    auth.mint()
    assert len(responses.calls) == 2


@responses.activate
def test_default_expires_in_when_omitted() -> None:
    """default_expiration fills in when the endpoint omits expires_in."""
    responses.add(
        responses.POST,
        TOKEN_ENDPOINT,
        json={"access_token": "at-abc"},
        status=200,
    )
    auth = _make_authenticator(default_expiration=600)
    auth.mint()
    assert auth.expires_in == 600


@responses.activate
def test_mint_raises_oauth_refresh_error_on_401() -> None:
    """401 responses are wrapped as OAuthTokenRefreshError without leaking secrets."""
    responses.add(
        responses.POST,
        TOKEN_ENDPOINT,
        json={"error": "invalid_grant", "error_description": "Refresh token expired"},
        status=401,
    )
    auth = _make_authenticator(refresh_token="rt-SHOULD_NOT_APPEAR")
    with pytest.raises(OAuthTokenRefreshError) as exc_info:
        auth.mint()
    message = str(exc_info.value)
    assert "401" in message
    assert "rt-SHOULD_NOT_APPEAR" not in message


@responses.activate
def test_handle_error_does_not_log_full_body(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Chatty IdP error bodies do not leak into logs."""
    chatty_payload = {
        "error": "invalid_grant",
        "error_description": "Refresh token was rt-LEAK-CANARY",
        "raw_request_echo": "client_secret=csec-test refresh_token=rt-LEAK-CANARY",
    }
    responses.add(
        responses.POST,
        TOKEN_ENDPOINT,
        body=json.dumps(chatty_payload),
        status=400,
    )
    auth = _make_authenticator(refresh_token="rt-LEAK-CANARY")
    caplog.set_level("DEBUG")
    with pytest.raises(OAuthTokenRefreshError):
        auth.mint()

    for record in caplog.records:
        rendered = record.getMessage()
        assert "rt-LEAK-CANARY" not in rendered
        assert "client_secret" not in rendered
        assert "raw_request_echo" not in rendered
        assert "error_description" not in rendered

    error_records = [r for r in caplog.records if r.levelname == "ERROR"]
    assert any("invalid_grant" in r.getMessage() for r in error_records)
    assert any("400" in r.getMessage() for r in error_records)


def test_mint_wraps_non_http_runtime_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Plain RuntimeError from update_access_token is wrapped."""
    auth = _make_authenticator()

    def boom(self: SnowflakeOAuthRefreshAuthenticator) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(
        SnowflakeOAuthRefreshAuthenticator,
        "update_access_token",
        boom,
    )
    with pytest.raises(OAuthTokenRefreshError) as exc_info:
        auth.mint()
    assert "boom" in str(exc_info.value)


def test_default_snowflake_endpoint() -> None:
    """The helper builds the documented Snowflake-internal URL."""
    assert default_snowflake_token_endpoint("myacct") == (
        "https://myacct.snowflakecomputing.com/oauth/token-request"
    )
