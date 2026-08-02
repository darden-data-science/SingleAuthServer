# Shared environment for both halves of the rig. Sourced by run-auth-server.sh
# and run-hub.sh — you normally don't run this directly.
#
# Both secrets below are FIXED AND FAKE on purpose: reproducible across restarts
# so cookies survive, and obviously not real so they can't be mistaken for
# production values. Never copy these anywhere.

# 32 bytes, hex. AuthHub reads this env var and hex-decodes it
# (binascii.a2b_hex); jupyterhub_config.py does bytes.fromhex on the same value.
export DEV_COOKIE_SECRET="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
export AUTH_COOKIE_SECRET="$DEV_COOKIE_SECRET"

# Required by c.Authenticator.enable_auth_state. Without it JupyterHub refuses
# to start when auth_state is enabled.
export JUPYTERHUB_CRYPT_KEY="ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"

# The DevProvider refuses to construct without this. See dev_provider.py.
export SINGLE_AUTH_DEV_PROVIDER=1
