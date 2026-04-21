"""Snowflake tap class."""

from singer_sdk import SQLTap
from singer_sdk import typing as th  # JSON schema typing helpers

from tap_snowflake.client import SnowflakeStream

SFLAKE_DOCS = "https://docs.snowflake.com/en/user-guide"


class TapSnowflake(SQLTap):
    """Snowflake tap class."""

    name = "tap-snowflake"
    package_name = "meltanolabs-tap-snowflake"

    # From https://docs.snowflake.com/en/user-guide/sqlalchemy.html#connection-parameters  # noqa: E501
    config_jsonschema = th.PropertiesList(
        th.Property(
            "user",
            th.StringType,
            required=False,
            description=(
                "The login name for your Snowflake user. Required for password, "
                "key-pair, and browser authentication; optional for OAuth. "
            ),
        ),
        th.Property(
            "password",
            th.StringType,
            required=False,
            secret=True,
            description=(
                "The password for your Snowflake user. One of [`password`, "
                "`private_key`, `private_key_path`, `access_token`, "
                "`refresh_token`] is required."
            ),
        ),
        th.Property(
            "private_key",
            th.StringType,
            required=False,
            secret=True,
            description=(
                "The private key is used to connect to snowflake. One of "
                "[`password`, `private_key`, `private_key_path`, `access_token`, "
                "`refresh_token`] is required."
            ),
        ),
        th.Property(
            "private_key_path",
            th.StringType,
            required=False,
            description=(
                "Path to where the private key is stored. The private key is used "
                "to connect to snowflake. One of [`password`, `private_key`, "
                "`private_key_path`, `access_token`, `refresh_token`] is required."
            ),
        ),
        th.Property(
            "private_key_passphrase",
            th.StringType,
            required=False,
            secret=True,
            description="The passprhase used to protect the private key",
        ),
        th.Property(
            "use_browser_authentication",
            th.BooleanType,
            required=False,
            default=False,
            description=(
                "If authentication should be done using SSO (via external browser). "
                "See SSO browser authentication."
            ),
        ),
        th.Property(
            "access_token",
            th.StringType,
            required=False,
            secret=True,
            description=(
                "Pre-minted OAuth 2.0 access token. Use when your orchestrator "
                "(Meltano Cloud, Airflow, etc.) manages the token lifecycle. "
                "Mutually exclusive with `refresh_token`."
            ),
        ),
        th.Property(
            "refresh_token",
            th.StringType,
            required=False,
            secret=True,
            description=(
                "Long-lived OAuth 2.0 refresh token. The tap mints short-lived "
                "access tokens by POSTing to `oauth_token_endpoint`. Requires "
                "`client_id` and `client_secret`."
            ),
        ),
        th.Property(
            "client_id",
            th.StringType,
            required=False,
            secret=True,
            description=(
                "OAuth 2.0 client identifier. Required when `refresh_token` is set."
            ),
        ),
        th.Property(
            "client_secret",
            th.StringType,
            required=False,
            secret=True,
            description=(
                "OAuth 2.0 client secret. Required when `refresh_token` is set."
            ),
        ),
        th.Property(
            "oauth_token_endpoint",
            th.StringType,
            required=False,
            description=(
                "OAuth 2.0 token endpoint URL. Defaults to "
                "`https://{account}.snowflakecomputing.com/oauth/token-request` "
                "for Snowflake-internal OAuth. Override for External OAuth "
                "(Okta, Azure AD, etc.)."
            ),
        ),
        th.Property(
            "oauth_scope",
            th.StringType,
            required=False,
            description=(
                "Optional `scope` parameter included in OAuth refresh requests. "
                "Omit unless your identity provider requires it."
            ),
        ),
        th.Property(
            "account",
            th.StringType,
            required=True,
            description=(
                "Your account identifier. See [Account Identifiers]"
                f"({SFLAKE_DOCS}/admin-account-identifier.html)."
            ),
        ),
        th.Property(
            "database",
            th.StringType,
            description="The initial database for the Snowflake session.",
        ),
        th.Property(
            "schema",
            th.StringType,
            description="The initial schema for the Snowflake session.",
        ),
        th.Property(
            "warehouse",
            th.StringType,
            description="The initial warehouse for the session.",
        ),
        th.Property(
            "role",
            th.StringType,
            description="The initial role for the session.",
        ),
        th.Property(
            "tables",
            th.ArrayType(th.StringType),
            description=(
                "An array of the table names that you want to sync. The table names "
                "should be fully qualified, including schema and table name. "
                "NOTE: this limits discovery to the tables specified, for performance "
                "reasons. Do not specify `tables` if you intend to discover the entire "
                "available catalog. See readme for more details on the tables "
                "configuration parameter."
            ),
        ),
    ).to_dict()
    default_stream_class = SnowflakeStream


if __name__ == "__main__":
    TapSnowflake.cli()
