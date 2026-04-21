"""Unit tests for SnowflakeConnector authentication wiring."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock, patch

import pytest
from singer_sdk.exceptions import ConfigValidationError

from tap_snowflake.client import SnowflakeAuthMethod, SnowflakeConnector

if TYPE_CHECKING:
    from collections.abc import Iterator

BASE_CONFIG: dict[str, Any] = {"account": "testacct"}


def make_connector(**overrides: Any) -> SnowflakeConnector:
    """Build a connector with a minimal config merged with overrides."""
    config = {**BASE_CONFIG, **overrides}
    return SnowflakeConnector(config=config)


@pytest.fixture
def mock_create_engine() -> Iterator[MagicMock]:
    """Patch sqlalchemy.create_engine so no real engine is built."""
    with patch("tap_snowflake.client.sqlalchemy.create_engine") as mock:
        mock.return_value = MagicMock()
        yield mock


@pytest.fixture
def mock_oauth_class() -> Iterator[MagicMock]:
    """Patch the OAuth authenticator class at its import site in client.py."""
    with patch(
        "tap_snowflake.client.SnowflakeOAuthRefreshAuthenticator",
    ) as mock_cls:
        mock_cls.return_value.mint.return_value = "at-MINTED"
        yield mock_cls


# --- auth_method detection -------------------------------------------------


def test_auth_method_oauth_via_access_token() -> None:
    """access_token in config selects OAUTH."""
    conn = make_connector(user="u", access_token="at-abc")
    assert conn.auth_method == SnowflakeAuthMethod.OAUTH


def test_auth_method_oauth_via_refresh_token() -> None:
    """refresh_token + client_id + client_secret selects OAUTH."""
    conn = make_connector(
        user="u",
        refresh_token="rt-abc",
        client_id="cid",
        client_secret="csec",
    )
    assert conn.auth_method == SnowflakeAuthMethod.OAUTH


def test_oauth_precedence_over_password_and_key_pair() -> None:
    """When OAuth fields and password are both set, OAuth wins."""
    conn = make_connector(user="u", access_token="at-abc", password="pw")
    assert conn.auth_method == SnowflakeAuthMethod.OAUTH


# --- OAuth config validation ----------------------------------------------


def test_oauth_rejects_access_token_and_refresh_token_together() -> None:
    """Both token fields set is a ConfigValidationError."""
    conn = make_connector(access_token="at", refresh_token="rt")
    with pytest.raises(ConfigValidationError, match="mutually exclusive"):
        _ = conn.auth_method


def test_oauth_refresh_token_requires_client_id() -> None:
    """refresh_token without client_id raises with field named."""
    conn = make_connector(refresh_token="rt", client_secret="csec")
    with pytest.raises(ConfigValidationError, match="client_id"):
        _ = conn.auth_method


def test_oauth_refresh_token_requires_client_secret() -> None:
    """refresh_token without client_secret raises with field named."""
    conn = make_connector(refresh_token="rt", client_id="cid")
    with pytest.raises(ConfigValidationError, match="client_secret"):
        _ = conn.auth_method


# --- Endpoint derivation --------------------------------------------------


def test_oauth_token_endpoint_defaults_to_snowflake_url(
    mock_oauth_class: MagicMock,
) -> None:
    """When omitted, the endpoint is derived from `account`."""
    conn = make_connector(refresh_token="rt", client_id="cid", client_secret="csec")
    conn._get_oauth_access_token()
    mock_oauth_class.assert_called_once_with(
        auth_endpoint=("https://testacct.snowflakecomputing.com/oauth/token-request"),
        client_id="cid",
        client_secret="csec",
        refresh_token="rt",
        oauth_scopes=None,
    )


def test_oauth_token_endpoint_override_respected(
    mock_oauth_class: MagicMock,
) -> None:
    """Explicit oauth_token_endpoint is used verbatim."""
    conn = make_connector(
        refresh_token="rt",
        client_id="cid",
        client_secret="csec",
        oauth_token_endpoint="https://custom.example/token",
    )
    conn._get_oauth_access_token()
    mock_oauth_class.assert_called_once()
    kwargs = mock_oauth_class.call_args.kwargs
    assert kwargs["auth_endpoint"] == "https://custom.example/token"


# --- Baseline / regression ------------------------------------------------


def test_none_configured_still_raises() -> None:
    """Empty auth config still raises the existing validation error."""
    conn = make_connector(user="u")
    with pytest.raises(
        ConfigValidationError,
        match="Neither password nor private key",
    ):
        _ = conn.auth_method


# --- create_engine wiring -------------------------------------------------


def test_create_engine_oauth_wires_connect_args(
    mock_create_engine: MagicMock,
    mock_oauth_class: MagicMock,
) -> None:
    """OAuth routes through connect_args with authenticator=oauth and token."""
    conn = make_connector(refresh_token="rt", client_id="cid", client_secret="csec")
    conn.create_engine()
    mock_create_engine.assert_called_once()
    connect_args = mock_create_engine.call_args.kwargs["connect_args"]
    assert connect_args["authenticator"] == "oauth"
    assert connect_args["token"] == "at-MINTED"
    assert "private_key" not in connect_args


def test_create_engine_oauth_keeps_token_out_of_url(
    mock_create_engine: MagicMock,
    mock_oauth_class: MagicMock,
) -> None:
    """Token and authenticator=oauth do not appear in the SQLAlchemy URL."""
    conn = make_connector(refresh_token="rt", client_id="cid", client_secret="csec")
    conn.create_engine()
    url = mock_create_engine.call_args.args[0]
    url_str = str(url)
    assert "at-MINTED" not in url_str
    assert "authenticator=oauth" not in url_str


def test_oauth_access_token_config_used_verbatim(
    mock_create_engine: MagicMock,
    mock_oauth_class: MagicMock,
) -> None:
    """access_token in config bypasses the refresh authenticator."""
    conn = make_connector(access_token="at-STATIC")
    conn.create_engine()
    connect_args = mock_create_engine.call_args.kwargs["connect_args"]
    assert connect_args["token"] == "at-STATIC"
    assert mock_oauth_class.call_count == 0


def test_oauth_authenticator_reused_across_connects(
    mock_create_engine: MagicMock,
    mock_oauth_class: MagicMock,
) -> None:
    """Two create_engine() calls reuse one authenticator instance."""
    conn = make_connector(refresh_token="rt", client_id="cid", client_secret="csec")
    conn.create_engine()
    conn.create_engine()
    assert mock_oauth_class.call_count == 1


def test_password_auth_still_works(mock_create_engine: MagicMock) -> None:
    """Regression: password auth still routes through the URL."""
    conn = make_connector(user="u", password="pw")
    assert conn.auth_method == SnowflakeAuthMethod.PASSWORD
    conn.create_engine()
    url_str = str(mock_create_engine.call_args.args[0])
    assert "pw" in url_str


def test_key_pair_auth_still_works(
    mock_create_engine: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: key-pair auth still passes private_key via connect_args."""
    monkeypatch.setattr(
        SnowflakeConnector,
        "get_private_key",
        lambda self: b"fake-der-bytes",
    )
    conn = make_connector(user="u", private_key="pem-content")
    assert conn.auth_method == SnowflakeAuthMethod.KEY_PAIR
    conn.create_engine()
    connect_args = mock_create_engine.call_args.kwargs["connect_args"]
    assert connect_args["private_key"] == b"fake-der-bytes"


# --- user field behaviour -------------------------------------------------


def test_user_optional_for_oauth(
    mock_create_engine: MagicMock,
    mock_oauth_class: MagicMock,
) -> None:
    """OAuth config without user builds a URL that omits user."""
    conn = make_connector(
        refresh_token="rt",
        client_id="cid",
        client_secret="csec",
    )
    conn.create_engine()
    url_str = str(mock_create_engine.call_args.args[0])
    assert "user" not in url_str.lower().split("?")[0].split("//", 1)[-1].split("@")[0]


def test_user_required_for_password_auth() -> None:
    """Password config without `user` raises a clear startup error."""
    conn = make_connector(password="pw")
    with pytest.raises(ConfigValidationError, match="user"):
        _ = conn.auth_method


def test_user_required_for_key_pair_auth() -> None:
    """Key-pair config without `user` raises the same error."""
    conn = make_connector(private_key="pem-content")
    with pytest.raises(ConfigValidationError, match="user"):
        _ = conn.auth_method


def test_user_required_for_browser_auth() -> None:
    """Browser auth without `user` raises the same error."""
    conn = make_connector(use_browser_authentication=True)
    with pytest.raises(ConfigValidationError, match="user"):
        _ = conn.auth_method
