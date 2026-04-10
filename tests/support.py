from tornado.httputil import url_concat
from traitlets import TraitError
from traitlets.config import Config

from SingleAuthServer.app import AuthHub
from SingleAuthServer.handlers import BaseHandler
from SingleAuthServer.provider import BaseAuthProvider

COOKIE_SECRET = b"0123456789abcdef0123456789abcdef"


class FakeProvider(BaseAuthProvider):
    callback_path = "/fake/callback"

    def begin_login(self, request_context):
        return url_concat(
            self.public_url(self.callback_path),
            {"state": request_context.state_token, "username": "alice"},
        )

    def get_handlers(self):
        return [(self.callback_path, FakeCallbackHandler)]


class FakeCallbackHandler(BaseHandler):
    def get(self):
        self.auth_hub.finalize_login(
            self,
            self.get_argument("username"),
            self.get_argument("state"),
        )


class BrokenProvider(BaseAuthProvider):
    def validate_configuration(self):
        raise TraitError("broken provider configuration")


class NotAProvider:
    pass


def build_auth_hub(extra_config=None, trait_overrides=None):
    hub = AuthHub()
    hub.update_config(
        Config(
            {
                "AuthHub": {
                    "provider_class": "tests.support.FakeProvider",
                    "public_base_url": "https://auth.example.test",
                }
            }
        )
    )
    if extra_config:
        hub.update_config(Config(extra_config))

    hub.cookie_secret = COOKIE_SECRET
    for trait_name, value in (trait_overrides or {}).items():
        setattr(hub, trait_name, value)

    hub.init_logging()
    hub.init_provider()
    hub.init_handlers()
    hub.init_tornado_settings()
    hub.init_tornado()
    return hub
