"""JupyterHub config for the local rig — the OTHER half of the wire contract.

This is a real JupyterHub running the real ExternalAuthenticator. Nothing is
mocked. If a login completes here, the contract genuinely works.
"""

import os

c = get_config()  # noqa: F821  (injected by traitlets)

# Public URL (the CHP proxy). This is what you open in a browser.
c.JupyterHub.bind_url = "http://127.0.0.1:8081"
# The hub's own internal port. Defaults to 8081, which would collide with the
# proxy above — JupyterHub fails with "Address already in use" if you leave it.
c.JupyterHub.hub_port = 8082

# --- The contract ---------------------------------------------------------
c.JupyterHub.authenticator_class = "ExternalAuthenticator.ExternalAuthenticator"
c.ExternalAuthenticator.login_service = "Dev Login"
c.ExternalAuthenticator.external_login_url = "http://127.0.0.1:8000/login"
c.ExternalAuthenticator.auth_token_valid_time = 300  # matches AuthHub.login_state_ttl

# THE shared secret. The auth server hex-decodes the same env var; JupyterHub
# wants raw bytes, hence fromhex. These must be byte-identical or every login
# fails with a 403 that looks like a code bug.
c.JupyterHub.cookie_secret = bytes.fromhex(os.environ["DEV_COOKIE_SECRET"])

# --- JupyterHub 5 requirements -------------------------------------------
# allow_all defaults to False in JH5: without it the user authenticates
# successfully and is then denied. Production sets this for authType=external
# at config_files/integration/jupyterhub/values.yaml.gotmpl:44.
c.Authenticator.allow_all = True

# ExternalAuthenticator stores its replay-protection token_history in
# auth_state. Without this (and JUPYTERHUB_CRYPT_KEY in the env) replay
# protection silently does nothing.
c.Authenticator.enable_auth_state = True

# --- Local-only plumbing --------------------------------------------------
# SimpleLocalProcessSpawner spawns as the CURRENT user regardless of the
# JupyterHub username, so you can log in as any name without needing a matching
# unix account. The default LocalProcessSpawner cannot do this.
c.JupyterHub.spawner_class = "simple"
c.Spawner.default_url = "/lab"

_here = os.path.dirname(os.path.abspath(__file__))
c.JupyterHub.db_url = "sqlite:///" + os.path.join(_here, "dev-jupyterhub.sqlite")
c.ConfigurableHTTPProxy.command = [
    os.path.join(_here, "node_modules", ".bin", "configurable-http-proxy")
]

c.Application.log_level = "DEBUG"
c.JupyterHub.log_level = "DEBUG"
