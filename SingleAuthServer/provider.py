from dataclasses import dataclass

from traitlets import TraitError
from traitlets.config import LoggingConfigurable
from traitlets.utils.importstring import import_item

from .utils import public_url_join


@dataclass(frozen=True)
class LoginRequestContext:
    return_url: str
    state_token: str
    public_base_url: str
    handler: object


class BaseAuthProvider(LoggingConfigurable):
    """Base class for pluggable authentication providers."""

    def __init__(self, auth_hub, **kwargs):
        self.auth_hub = auth_hub
        super().__init__(parent=auth_hub, config=auth_hub.config, **kwargs)

    def validate_configuration(self):
        """Raise if the provider configuration is invalid."""

    def begin_login(self, request_context):
        raise NotImplementedError()

    def get_handlers(self):
        return []

    def public_url(self, *pieces):
        return public_url_join(self.auth_hub.public_base_url, *pieces)


def load_provider_class(provider_class):
    try:
        provider = import_item(provider_class)
    except Exception as exc:
        raise TraitError(
            f"Could not import provider_class {provider_class!r}: {exc}"
        ) from exc

    if not isinstance(provider, type) or not issubclass(provider, BaseAuthProvider):
        raise TraitError(
            f"provider_class {provider_class!r} must inherit from "
            "SingleAuthServer.provider.BaseAuthProvider."
        )

    return provider
