"""OAuth 2.0 refresh-token flow for Snowflake authentication.

Builds on :class:`singer_sdk.authenticators.OAuthAuthenticator` to mint
short-lived Snowflake access tokens from a refresh token. The Snowflake
Python connector accepts the minted token via ``authenticator=oauth`` +
``token=<access_token>`` connection arguments; this module is responsible
only for producing that access token on demand.
"""

from __future__ import annotations

import json
from typing import Any, cast

from singer_sdk.authenticators import OAuthAuthenticator
from singer_sdk.exceptions import ConfigValidationError


class OAuthTokenRefreshError(ConfigValidationError):
    """Raised when minting a Snowflake OAuth access token fails.

    Subclasses :class:`ConfigValidationError` so that transport and
    protocol failures surface through the same fail-fast path as other
    startup errors in the tap.
    """


def default_snowflake_token_endpoint(account: str) -> str:
    """Return the default Snowflake-internal OAuth token endpoint.

    Args:
        account: The Snowflake account identifier.

    Returns:
        The default token endpoint URL for Snowflake-internal OAuth.
    """
    return f"https://{account}.snowflakecomputing.com/oauth/token-request"


class SnowflakeOAuthRefreshAuthenticator(OAuthAuthenticator):
    """OAuth 2.0 refresh-token authenticator for Snowflake.

    Subclasses the Singer SDK's :class:`OAuthAuthenticator` without any
    REST-tap coupling: no ``stream`` is required, and the inherited
    ``update_access_token`` method uses :func:`requests.post` directly.
    The SQL tap calls :meth:`mint` to retrieve a valid access token and
    passes it to the Snowflake driver via ``connect_args``.
    """

    def __init__(  # noqa: PLR0913
        self,
        *,
        auth_endpoint: str,
        client_id: str,
        client_secret: str,
        refresh_token: str,
        oauth_scopes: str | None = None,
        default_expiration: int = 600,
    ) -> None:
        """Initialize the authenticator.

        Args:
            auth_endpoint: OAuth 2.0 token endpoint URL.
            client_id: OAuth 2.0 client identifier.
            client_secret: OAuth 2.0 client secret.
            refresh_token: Long-lived refresh token used to mint access
                tokens.
            oauth_scopes: Optional ``scope`` value included in the refresh
                request.
            default_expiration: Fallback ``expires_in`` (seconds) used
                when the token endpoint omits the value. Snowflake's
                documented default is 600 seconds.
        """
        super().__init__(
            auth_endpoint=auth_endpoint,
            client_id=client_id,
            client_secret=client_secret,
            oauth_scopes=oauth_scopes,
            default_expiration=default_expiration,
        )
        self._refresh_token = refresh_token

    @property
    def oauth_request_body(self) -> dict:
        """Build the RFC 6749 §6 refresh-token request body.

        Returns:
            Form-encoded fields for the token endpoint POST.
        """
        body: dict[str, str] = {
            "grant_type": "refresh_token",
            "refresh_token": self._refresh_token,
            "client_id": cast("str", self._client_id),
            "client_secret": cast("str", self._client_secret),
        }
        if self._oauth_scopes:
            body["scope"] = self._oauth_scopes
        return body

    def handle_error(self, *, content: str, status_code: int) -> None:
        """Log an OAuth error without leaking the response body.

        The parent implementation logs up to 1000 chars of ``content``
        verbatim. Some IdPs echo submitted fields (including the
        refresh token) back in ``error_description``, so we log only
        the HTTP status and, when the body parses as JSON, the RFC
        6749 ``error`` code. Free-form description text is deliberately
        omitted to guarantee secrets never reach logs.

        Args:
            content: The raw response body from the token endpoint.
            status_code: The HTTP status code returned by the endpoint.
        """
        error_code = "unknown"
        try:
            payload: Any = json.loads(content)
        except (ValueError, TypeError):
            payload = None
        if isinstance(payload, dict):
            raw_code = payload.get("error")
            if isinstance(raw_code, str):
                error_code = raw_code
        self.logger.error(
            "OAuth token refresh failed (status=%d, error=%s)",
            status_code,
            error_code,
        )

    def mint(self) -> str:
        """Return a valid access token, refreshing if needed.

        Delegates memoization to the inherited :meth:`is_token_valid`
        check, which uses ``last_refreshed`` + ``expires_in``. Wraps the
        parent's ``RuntimeError`` in :class:`OAuthTokenRefreshError`
        so callers see the Singer SDK fail-fast error type.

        Returns:
            A Snowflake OAuth access token string.

        Raises:
            OAuthTokenRefreshError: If the token endpoint rejects the
                refresh request or returns an unparseable response.
        """
        try:
            if not self.is_token_valid():
                self.update_access_token()
        except RuntimeError as exc:
            msg = f"Failed to mint Snowflake OAuth access token: {exc}"
            raise OAuthTokenRefreshError(msg) from exc
        return cast("str", self.access_token)
