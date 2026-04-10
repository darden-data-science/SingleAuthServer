# Single Auth Server

SingleAuthServer is a small Tornado application that acts as a trusted external
login service for another Tornado-based app, such as JupyterHub via
[ExternalAuthenticator](https://github.com/darden-data-science/ExternalAuthenticator).

The core server accepts a downstream `return-url`, delegates authentication to a
configured provider, verifies the downstream `signed-return-url` proof, sets a
secure `auth-token` cookie with the shared Tornado `cookie_secret`, and
redirects the browser back to the verified return URL.

This repository now has two layers:

- `SingleAuthServer`: provider-agnostic core server and signed login-state flow.
- `single_auth_saml`: plugin-style SAML provider with its own config and routes.

The core server keeps SQL-backed auth state so providers can persist security
data such as replay-protection history.

## Installation

Create or sync the local environment for the core server:

```bash
uv sync
```

Sync the core server with the bundled SAML provider dependencies:

```bash
uv sync --extra saml
```

## Core Configuration

At minimum, configure the public URL and the provider import path:

```python
c.AuthHub.public_base_url = "https://auth.example.com"
c.AuthHub.provider_class = "single_auth_saml.provider.SAMLProvider"
```

Available core settings include:

- `c.AuthHub.port`
- `c.AuthHub.db_url`
- `c.AuthHub.public_base_url`
- `c.AuthHub.provider_class`
- `c.AuthHub.cookie_secret` or `AUTH_COOKIE_SECRET`
- `c.AuthHub.auth_token_name`
- `c.AuthHub.login_state_name`
- `c.AuthHub.login_state_ttl`
- `c.AuthHub.signed_return_url_name`
- `c.AuthHub.auth_token_cookie_domain`

## SAML Provider Configuration

Provider-specific settings live under `c.SAMLProvider.*`:

```python
c.SAMLProvider.callback_path = "/auth/callback"
c.SAMLProvider.metadata_path = "/auth/metadata"
c.SAMLProvider.idp_metadata_url = "https://idp.example.com/metadata"
c.SAMLProvider.xpath_username_location = (
    '//samlp:Response/saml:Assertion/saml:AttributeStatement/'
    'saml:Attribute[@FriendlyName="uid"]/saml:AttributeValue/text()'
)
c.SAMLProvider.saml_settings = {
    "strict": True,
    "debug": False,
    "sp": {
        "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
        "x509cert": "...",
        "privateKey": "...",
    },
}
```

The SAML provider derives the SP metadata URL and assertion consumer URL from
`c.AuthHub.public_base_url`, `c.SAMLProvider.metadata_path`, and
`c.SAMLProvider.callback_path`.

## Runtime Flow

1. `GET /login?return-url=<hub callback URL with signed-return-url proof>`
   creates a short-lived signed login-state token.
2. The configured provider starts authentication and round-trips that token.
3. On success, the core verifies the login state, validates the downstream
   `signed-return-url`, sets the `auth-token` secure cookie for the destination
   server domain, and redirects back to the verified return URL.

The `auth-token` payload is JSON:

```json
{
  "username": "alice",
  "return_url": "https://hub.example.com/jupyter/hub/external-login"
}
```

## Development

Run the tests with:

```bash
uv run -m unittest discover -s tests -v
```
