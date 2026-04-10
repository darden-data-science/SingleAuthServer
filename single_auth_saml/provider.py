import os
from copy import deepcopy
from urllib.parse import urlparse

from tornado import web
from traitlets import Dict, TraitError, Unicode, validate

from SingleAuthServer.handlers import BaseHandler
from SingleAuthServer.provider import BaseAuthProvider

try:
    from lxml import etree
except ImportError:  # pragma: no cover - exercised through provider validation
    etree = None

try:
    from onelogin.saml2.auth import OneLogin_Saml2_Auth
    from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser
except ImportError:  # pragma: no cover - exercised through provider validation
    OneLogin_Saml2_Auth = None
    OneLogin_Saml2_IdPMetadataParser = None


class SAMLProvider(BaseAuthProvider):
    callback_path = Unicode(
        default_value="/auth/callback",
        help="Route that receives the SAML assertion consumer response.",
    ).tag(config=True)

    metadata_path = Unicode(
        default_value="/auth/metadata",
        help="Route that serves SP metadata.",
    ).tag(config=True)

    saml_custom_base_path = Unicode(
        default_value=os.getcwd(),
        help="""
        Path to custom SAML settings and cert material expected by python3-saml.
        """,
    ).tag(config=True)

    saml_settings = Dict(
        default_value={},
        help="Base python3-saml settings for this provider.",
    ).tag(config=True)

    saml_namespace = Dict(
        default_value={
            "ds": "http://www.w3.org/2000/09/xmldsig#",
            "md": "urn:oasis:names:tc:SAML:2.0:metadata",
            "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
            "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
        },
        help="Namespace map used for username extraction XPath.",
    ).tag(config=True)

    xpath_username_location = Unicode(
        default_value="//saml:NameID/text()",
        help="XPath used to extract the authenticated username from the response.",
    ).tag(config=True)

    idp_metadata_url = Unicode(
        default_value=None,
        allow_none=True,
        help="Optional IdP metadata URL to fetch and merge into saml_settings.",
    ).tag(config=True)

    @validate("callback_path", "metadata_path")
    def _validate_path(self, proposal):
        value = proposal["value"]
        if not value.startswith("/"):
            raise TraitError(f"{proposal['trait'].name} must start with '/'.")
        return value

    def _require_dependencies(self):
        missing = []
        if etree is None:
            missing.append("lxml")
        if OneLogin_Saml2_Auth is None:
            missing.append("python3-saml")
        if missing:
            packages = ", ".join(missing)
            raise TraitError(
                f"SAMLProvider requires optional dependencies: {packages}."
            )

    def validate_configuration(self):
        self._require_dependencies()
        self._cached_saml_settings = self._build_saml_settings()

    def get_handlers(self):
        return [
            (self.callback_path, SAMLCallbackHandler),
            (self.metadata_path, SAMLMetadataHandler),
        ]

    def begin_login(self, request_context):
        auth = self.init_saml_auth(request_context.handler.request)
        return auth.login(request_context.state_token)

    def prepare_tornado_request(self, request):
        base_url = urlparse(self.auth_hub.public_base_url)
        default_port = 443 if base_url.scheme == "https" else 80
        server_port = str(base_url.port or default_port)

        data = {}
        for key, values in request.arguments.items():
            data[key] = values[0].decode("utf-8")

        return {
            "https": "on" if base_url.scheme == "https" else "off",
            "http_host": base_url.hostname,
            "script_name": request.path,
            "server_port": server_port,
            "get_data": data,
            "post_data": data,
            "query_string": request.query,
        }

    def _build_saml_settings(self):
        settings = deepcopy(self.saml_settings)
        sp_settings = settings.setdefault("sp", {})
        assertion_consumer = sp_settings.setdefault("assertionConsumerService", {})
        assertion_consumer["url"] = self.public_url(self.callback_path)
        assertion_consumer.setdefault(
            "binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        )
        sp_settings["entityId"] = self.public_url(self.metadata_path)

        if self.idp_metadata_url:
            if OneLogin_Saml2_IdPMetadataParser is None:
                raise TraitError(
                    "SAMLProvider requires python3-saml to fetch IdP metadata."
                )
            idp_data = OneLogin_Saml2_IdPMetadataParser.parse_remote(
                self.idp_metadata_url
            )
            settings = OneLogin_Saml2_IdPMetadataParser.merge_settings(
                settings, idp_data
            )

        return settings

    def get_saml_settings(self):
        if not hasattr(self, "_cached_saml_settings"):
            self._cached_saml_settings = self._build_saml_settings()
        return deepcopy(self._cached_saml_settings)

    def init_saml_auth(self, request):
        self.log.debug("SAML custom base path is %r", self.saml_custom_base_path)
        return OneLogin_Saml2_Auth(
            self.prepare_tornado_request(request),
            old_settings=self.get_saml_settings(),
            custom_base_path=self.saml_custom_base_path,
        )

    def extract_username(self, response_xml):
        tree = etree.fromstring(response_xml)
        usernames = tree.xpath(
            self.xpath_username_location, namespaces=self.saml_namespace
        )
        if not usernames or not usernames[0]:
            raise web.HTTPError(
                404,
                log_message=(
                    "SAML is valid, but it does not contain a username at the "
                    "configured xpath."
                ),
            )
        return usernames[0]


class SAMLCallbackHandler(BaseHandler):
    def post(self):
        auth = self.provider.init_saml_auth(self.request)

        auth.process_response()
        errors = auth.get_errors()
        if errors:
            self.log.warning("SAML response errors:\n%s", "\n".join(errors))
            self.log.warning("Last SAML error reason: %r", auth.get_last_error_reason())

        if not auth.is_authenticated():
            self.log.warning("Unauthorized SAML login attempt.")
            raise web.HTTPError(403, log_message="Unauthorized login attempt.")

        state_token = self.get_argument("RelayState", "")
        if not state_token:
            self.log.warning("RelayState not present in SAML callback.")
            raise web.HTTPError(400, log_message="Missing RelayState.")

        username = self.provider.extract_username(auth.get_last_response_xml())
        self.auth_hub.finalize_login(self, username, state_token)


class SAMLMetadataHandler(BaseHandler):
    def get(self):
        auth = self.provider.init_saml_auth(self.request)
        saml_settings = auth.get_settings()
        metadata = saml_settings.get_sp_metadata()
        errors = saml_settings.validate_metadata(metadata)
        self.log.info("SAML metadata requested.")

        if errors:
            self.write(", ".join(errors))
            return

        self.set_header("Content-Type", "text/xml")
        self.write(metadata)
