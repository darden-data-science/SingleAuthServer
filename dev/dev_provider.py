"""A no-SAML auth provider for local testing.

Swaps out ONLY the identity step. Everything downstream — signed login state
with TTL and nonce, the signed-return-url proof, the auth-token cookie, replay
protection — is the same production code path SAMLProvider uses.

    !!  THIS IS A LOGIN BYPASS. Anyone can become any user by typing a name.  !!
    !!  It lives in dev/, which is excluded from the package and the image.   !!

Structurally undeployable, by three separate mechanisms:
  1. dev/ is not in [tool.setuptools.packages.find] in ../pyproject.toml
  2. dev/ is in ../.dockerignore
  3. it refuses to construct unless SINGLE_AUTH_DEV_PROVIDER=1 is set
"""

import html
import os

from tornado import web
from tornado.httputil import url_concat
from traitlets import TraitError, Unicode

from SingleAuthServer.handlers import BaseHandler
from SingleAuthServer.provider import BaseAuthProvider

_ENABLE_ENV = "SINGLE_AUTH_DEV_PROVIDER"


class DevProvider(BaseAuthProvider):
    """Presents a username box instead of redirecting to an IdP."""

    login_path = Unicode(
        default_value="/dev/login",
        help="Route serving the fake login form.",
    ).tag(config=True)

    def __init__(self, auth_hub, **kwargs):
        super().__init__(auth_hub, **kwargs)
        if os.environ.get(_ENABLE_ENV) != "1":
            raise TraitError(
                f"DevProvider is a login bypass and refuses to start unless "
                f"{_ENABLE_ENV}=1 is set in the environment. If you are seeing "
                f"this anywhere other than a local dev machine, something is "
                f"badly wrong: this class must never reach a deployed server."
            )
        self.log.warning(
            "*** DevProvider active: authentication is BYPASSED. Local use only. ***"
        )

    def begin_login(self, request_context):
        # The state token is the signed, TTL-bounded login state minted by
        # AuthHub.issue_login_state(). We hand it straight back on the form so
        # the POST can return it unmodified, exactly as SAML does via RelayState.
        return url_concat(
            self.public_url(self.login_path),
            {"state": request_context.state_token},
        )

    def get_handlers(self):
        return [(self.login_path, DevLoginHandler)]


_FORM = """<!doctype html>
<title>Dev login</title>
<style>
 body {{ font-family: system-ui, sans-serif; max-width: 32rem; margin: 4rem auto; }}
 .warn {{ background: #fee; border: 1px solid #c00; padding: .75rem; border-radius: 4px; }}
 input, button {{ font-size: 1rem; padding: .4rem; }}
</style>
<p class="warn"><strong>Dev login — authentication is bypassed.</strong>
Type any username to become that user.</p>
<form method="post">
  <input type="hidden" name="state" value="{state}">
  <label>Username <input name="username" value="alice" autofocus></label>
  <button type="submit">Log in</button>
</form>
"""


class DevLoginHandler(BaseHandler):
    """GET shows the form; POST completes the login.

    Note the auth server does not enable tornado's xsrf_cookies, so this form
    needs no token. If that ever changes, this handler must be updated.
    """

    def get(self):
        state = self.get_argument("state", "")
        if not state:
            raise web.HTTPError(400, log_message="Missing state.")
        self.set_header("Content-Type", "text/html; charset=UTF-8")
        self.write(_FORM.format(state=html.escape(state, quote=True)))

    def post(self):
        username = self.get_argument("username", "").strip()
        state = self.get_argument("state", "")
        if not username:
            raise web.HTTPError(400, log_message="Missing username.")

        # Hands off to the real production path: decodes and TTL-checks the
        # login state, verifies the signed-return-url proof, sets auth-token,
        # and redirects back to the hub.
        self.auth_hub.finalize_login(self, username, state)
