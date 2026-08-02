# Local auth test rig

Runs the **real** SingleAuthServer and the **real** ExternalAuthenticator against each
other, on your laptop, with no SAML and no contact with UVA's IdP.

Everything installs into `dev/.venv` (Python, via uv) and `dev/node_modules` (the
JupyterHub proxy, via npm — local, never `-g`). Nothing touches system packages.

## Why this exists

The wire contract between the auth server and the hub is the most fragile part of the
system and, until now, the only part with **zero** coverage on both sides at once:

- `tests/` in this repo fakes the hub side.
- `ExternalAuthenticator/tests/` fakes JupyterHub entirely via `sys.modules` stubs.

Neither ever ran the two real implementations together. This rig does.

## What is and isn't faked

**Faked: the identity step only.** `DevProvider` shows a username box instead of
redirecting to NetBadge.

**Real: everything else.** Signed login state with TTL and nonce, the signed-return-url
proof, the `auth-token` cookie, the shared `cookie_secret`, JupyterHub's Authenticator
machinery, session creation. This is the production code path with one pluggable piece
swapped — which is the whole point of the provider refactor.

## Setup (once)

```bash
cd dev && uv sync && npm install
```

`uv sync` builds `dev/.venv` with a local editable install of SingleAuthServer (so edits
to this checkout are picked up live) and ExternalAuthenticator from its GitHub default
branch — the same source `images/hub/Dockerfile` installs into the hub image.

To test **local** ExternalAuthenticator edits instead, flip the commented
`[tool.uv.sources]` entry in `dev/pyproject.toml` to the path dependency and re-run
`uv sync`.

## Run

Two terminals:

```bash
cd dev && ./run-auth-server.sh
```

```bash
cd dev && ./run-hub.sh
```

Then open **http://127.0.0.1:8081**, click *Sign in with Dev Login*, type any username.
A successful login lands you in JupyterLab.

## Automated check

With both servers running:

```bash
cd dev && ./smoke-test.sh
```

Drives a full login with curl and asserts 11 properties of the contract — the redirect
chain, the signed-return-url proof, cookie handoff, session creation, and three negative
cases (tampered state, off-host redirect, unproven return-url). Exits non-zero on
failure, so it works in CI.

## Layout

| File | Role |
|---|---|
| `pyproject.toml` | the rig's own uv project — `package = false`, so it is not installable |
| `dev_provider.py` | the no-SAML provider (**a login bypass**) |
| `authhub_config.py` | auth server config — mirrors what the helm chart must emit |
| `jupyterhub_config.py` | the other half of the contract |
| `env.sh` | the shared cookie secret + crypt key (fixed and fake) |
| `package.json` | local-only `configurable-http-proxy` |
| `smoke-test.sh` | the automated contract check |

## Why DevProvider can't reach production

It is a login bypass — anyone can become any user. Three independent guards:

1. `dev/` is not in `[tool.setuptools.packages.find]` in `../pyproject.toml`, so it is
   never in the wheel.
2. `dev/` is in `../.dockerignore`, so `COPY .` never puts it in an image.
3. It raises `TraitError` on construction unless `SINGLE_AUTH_DEV_PROVIDER=1` is set.

The secrets in `env.sh` are fixed and obviously fake so cookies survive restarts and
can't be mistaken for real values.

## Ports

| Port | What |
|---|---|
| 8000 | auth server |
| 8081 | JupyterHub public (CHP proxy) |
| 8082 | JupyterHub internal — **must differ from 8081**, or startup fails with `Address already in use` |

## Gotchas

**The cookie secret must be byte-identical on both sides.** The auth server hex-decodes
`AUTH_COOKIE_SECRET`; `jupyterhub_config.py` does `bytes.fromhex()` on the same value.
A mismatch produces a 403 that looks like a code bug. In production this is `cookieSecret`
from SOPS, fanned out to three helm releases at once.

**The cookie clear may no-op locally, and that is not a bug in this repo.** The server
sets the `auth-token` cookie with `domain=<hostname>` (port excluded,
`SingleAuthServer/app.py:407`), while ExternalAuthenticator clears it with
`domain=request.host`, which *includes* `:8081`. Production hides this because port 443
is implicit. If you see the cookie linger, that is the long-standing EA bug — the rig
just exposes it.

**JupyterHub 5 needs three things** or you will chase ghosts: `allow_all = True`,
`enable_auth_state = True`, and `JUPYTERHUB_CRYPT_KEY` exported. `env.sh` handles the
last one.

## Known gap this rig documented

`AuthHub.issue_login_state()` mints a `nonce` that `decode_login_state()` only
type-checks — it is never recorded or compared. A login-state token can therefore be
replayed within its 300s TTL at the AuthHub layer.

Not exploitable through SAML: replay is caught by the message-ID check in
`single_auth_saml/provider.py:185`, and the username comes from the signed assertion
rather than the caller. It matters only for providers where the caller supplies the
username — like this one. Worth closing as defense-in-depth; not a blocker.
