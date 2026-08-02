<!-- last-verified: 2026-08-02 against 4a881f0 (codex/refactor-auth-server) -->

# SingleAuthServer

> ## ⚠ Read before changing anything
>
> **This checkout is on the unmerged branch `codex/refactor-auth-server`.** `origin/master` is
> still `1e574d9` (2021), and the deployed DockerHub image `albertmichaelj/saml_single_auth_server:latest`
> is built from **master**, not from this branch.
>
> The consuming helm chart — `auth-server/templates/configmap.yaml` in the `jupyterhub-config-darden`
> repo — emits pre-refactor config keys: `AuthHub.{auto_IdP_metadata, metadata_url,
> xpath_username_location, force_https, saml_settings, saml_custom_base_path}`. This refactor
> moved all of them to `SAMLProvider` and made `provider_class` + `public_base_url` mandatory
> (`SingleAuthServer/app.py:225-228` hard-raises `TraitError`).
>
> **Merging this branch without updating that chart in the same change takes authentication down
> for every cohort.** See `docs/SYSTEM-MAP.md` → recipe 2 in the config repo.

## Where this fits

The cluster-wide SAML login service. One instance serves every JupyterHub cohort — it does SAML
once and hands identities to each hub, so no hub carries SAML machinery.

**My half of Contract A:** I expose `/login`, which requires an absolute http(s) `return-url`
query arg (400 otherwise). I mint login state — `{"return_url", "iat", "nonce"}` signed under the
name `login-state`, TTL **300s** — and carry it through SAML as RelayState. On a successful
callback I verify the caller's `signed-return-url` proof against the return URL with query and
fragment stripped, then set cookie **`auth-token`** = a Tornado-signed
`{"username", "return_url"}`, HttpOnly, session-scoped, and redirect back.

**Trust model:** I share the hub's Tornado `cookie_secret`. No bearer tokens, no API keys. That
means every hub trusts me completely, and rotating the secret must happen across all consumers
simultaneously.

**Who consumes me:** `ExternalAuthenticator` (repo `darden-data-science/ExternalAuthenticator`)
holds the other half. Deployed by the `auth-server/` helm chart in `jupyterhub-config-darden`.

**Full system map:** `/Users/Michael/Documents/Git Projects/Darden Jupyterhub/docs/SYSTEM-MAP.md`
(repo `darden-data-science/jupyterhub-config-darden`, private).

## Naming — three different strings

| Thing | Value |
|---|---|
| Local directory | `Single Auth Server` — **has spaces, quote every bash reference** |
| Git remote | `darden-data-science/SingleAuthServer` |
| Python packages | `SingleAuthServer/` (core) and `single_auth_saml/` (SAML provider) |
| Helm chart (other repo) | `auth-server/` |

## Architecture

Raw Tornado 6 + traitlets `Application`, patterned on JupyterHub's own `app.py`. **Not** Flask,
FastAPI, or JupyterHub app machinery.

The refactor split it into a pluggable-provider design:

```
SingleAuthServer/app.py          AuthHub: config, cookie secret, login-state issue/decode,
                                 signed-return-url verification, finalize_login
SingleAuthServer/provider.py     BaseAuthProvider, LoginRequestContext, load_provider_class()
SingleAuthServer/handlers/core.py  BaseHandler, LoginHandler, HealthCheckHandler, Template404
SingleAuthServer/orm.py          SQLAlchemy 2.0 User(id, username, auth_state JSON)
single_auth_saml/provider.py     SAMLProvider + callback/metadata handlers (optional `saml` extra)
```

`AuthHub` is provider-agnostic: `init_handlers` registers `/login`, then splices in
`self.provider.get_handlers()`, then `/health` and a catch-all 404. Adding a non-SAML IdP means a
new `BaseAuthProvider` subclass, not a fork.

The SQLite DB exists only for SAML replay protection (`saml_message_history` in `auth_state`).

## Commands

```bash
uv sync --extra saml
```

```bash
uv run -m unittest discover -s tests -v
```

20 real tests. `tests/test_core.py` (`AsyncHTTPTestCase`) covers the return-url 400s, the happy
path with cookie-attribute assertions, tampered/expired state → 403, signed-return-url tampering,
and login-state replay → 403. `tests/test_saml_provider.py` fakes `etree` and the OneLogin classes
via `mock.patch.object`. `tests/support.py` has the fixtures and an in-memory `sqlite://` factory.

**Local end-to-end rig — `dev/`.** Runs this server and a real JupyterHub with the real
ExternalAuthenticator against each other, with SAML swapped for a dev provider so no IdP is
involved. `cd dev && uv sync && npm install`, then the two run scripts, then `./smoke-test.sh`
(13 assertions, exits non-zero on failure). This is the only thing that tests both halves of the
wire contract at once — the unit suites on each side mock the other. See `dev/README.md`.

## Building the image

```bash
./build-image.sh          # add --push to publish
```

Tags every build three ways: `:<version>` (from `_version.py`), `:sha-<short commit>`, and
`:latest`. **Pin the helm chart to `:sha-<short>` or `:<version>`, never `:latest`** — the chart
historically tracked `:latest`, which is why there was no rollback path. OCI labels and the
`SINGLE_AUTH_SERVER_GIT_SHA` env var are baked in, so `docker inspect` and the startup log both
identify the exact commit. The script refuses to `--push` from a dirty tree.

## Known issues

- **No CI.** No `.github/` at all. `ExternalAuthenticator` has a workflow worth copying.
- `Dockerfile` is `FROM ubuntu:20.04` — **EOL April 2025**, ships Python 3.8 which is also EOL.
  Biggest remaining modernization item.
- Deprecated Tornado: `get_secure_cookie`/`set_secure_cookie` (renamed in 6.3 —
  `ExternalAuthenticator.py:15-27` has a compat shim to copy), `IOLoop.instance()`,
  `add_callback_from_signal()` (deprecated 6.4, removed in 7.0), and `server._connections`.
  None break on Tornado 6.5; all break on 7.
- `app.py` verifies `signed-return-url` with Tornado's default `max_age_days=31`, so a hub's
  return-URL proof stays valid for a month while `login_state_ttl` is 300s. Low severity — the
  proof asserts a URL, not a session — but the asymmetry is unintentional.
- `single_auth_saml/provider.py:137` does a **blocking** `parse_remote()` HTTP fetch. Normally
  cached at startup, but `get_saml_settings()` will re-call it inside a request if the cache is
  empty.
- `LoginStateNonce` rows are pruned opportunistically, on redemption. A server that issues login
  states and then goes idle keeps expired rows until the next login. Bounded and harmless, but
  not self-cleaning.

## Do not commit

`certs/` (contains `sp.key`, the SAML SP private key) and `auth_config.json` (embeds the SP
private key in plaintext at line 46) are **untracked but NOT gitignored**, and this remote is
**public**. A `git add -A` publishes SP key material. `auth_config.json` is also the *old*
pre-refactor config shape — `authhub_config.py` is the current example.
