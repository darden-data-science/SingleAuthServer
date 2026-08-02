"""AuthHub config for the local rig. Mirrors the shape the helm chart must produce.

The four keys under "REQUIRED BY THE REFACTOR" are exactly what
auth-server/templates/configmap.yaml in the jupyterhub-config repo does NOT
emit today. If you delete them, AuthHub.validate_runtime_configuration() raises
TraitError at startup — which is precisely the production failure that merging
the refactor without updating the chart would cause.
"""

import os

c = get_config()  # noqa: F821  (injected by traitlets)

# --- REQUIRED BY THE REFACTOR --------------------------------------------
# Both are new in the pluggable-provider design and have no default.
c.AuthHub.provider_class = "dev_provider.DevProvider"
c.AuthHub.public_base_url = "http://127.0.0.1:8000"

# --- Moved from AuthHub.* to the provider by the refactor ----------------
# In production these carry the real SAML settings. Pin callback_path and
# metadata_path to the CURRENT deployed routes so the SP registration with
# NetBadge stays valid — see docs/SYSTEM-MAP.md in the config repo.
c.DevProvider.login_path = "/dev/login"

# --- Unchanged across the refactor ---------------------------------------
c.AuthHub.port = 8000
c.AuthHub.db_url = "sqlite:///" + os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "dev-authhub.sqlite"
)

# Shared with JupyterHub. Read from the env as a HEX string and decoded by
# AuthHub.init_secrets() via binascii.a2b_hex — the hub side must therefore use
# bytes.fromhex() on the same value. Mismatch here = every login fails with an
# opaque 403.
c.AuthHub.cookie_secret_file = ""  # don't write a secret file in dev

c.Application.log_level = "DEBUG"
