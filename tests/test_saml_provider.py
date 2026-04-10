import json
from http.cookies import SimpleCookie
import time
from unittest import mock
from urllib.parse import parse_qs, quote, urlencode, urlparse

from tornado.testing import AsyncHTTPTestCase
from tornado.web import decode_signed_value

import single_auth_saml.provider as saml_provider_module
from tests.support import build_auth_hub, make_signed_return_url


class FakeEtreeTree:
    def xpath(self, xpath, namespaces=None):
        FakeEtree.last_xpath = xpath
        FakeEtree.last_namespaces = namespaces
        if FakeEtree.username is None:
            return []
        return [FakeEtree.username]


class FakeEtree:
    username = "alice"
    last_xml = None
    last_xpath = None
    last_namespaces = None

    @classmethod
    def reset(cls):
        cls.username = "alice"
        cls.last_xml = None
        cls.last_xpath = None
        cls.last_namespaces = None

    @staticmethod
    def fromstring(xml):
        FakeEtree.last_xml = xml
        return FakeEtreeTree()


class FakeMetadataSettings:
    metadata = "<EntityDescriptor />"
    errors = []

    def get_sp_metadata(self):
        return self.metadata

    def validate_metadata(self, metadata):
        return list(self.errors)


class FakeSAMLAuth:
    authenticated = True
    errors = []
    last_error_reason = ""
    response_xml = b"<Response />"
    message_id = "message-1"
    assertion_not_on_or_after = int(time.time()) + 300
    last_login_return_to = None
    last_request = None
    last_settings = None
    last_custom_base_path = None

    @classmethod
    def reset(cls):
        cls.authenticated = True
        cls.errors = []
        cls.last_error_reason = ""
        cls.response_xml = b"<Response />"
        cls.message_id = "message-1"
        cls.assertion_not_on_or_after = int(time.time()) + 300
        cls.last_login_return_to = None
        cls.last_request = None
        cls.last_settings = None
        cls.last_custom_base_path = None
        FakeMetadataSettings.metadata = "<EntityDescriptor />"
        FakeMetadataSettings.errors = []

    def __init__(self, request_data, old_settings=None, custom_base_path=None):
        type(self).last_request = request_data
        type(self).last_settings = old_settings
        type(self).last_custom_base_path = custom_base_path

    def login(self, return_to):
        type(self).last_login_return_to = return_to
        return (
            "https://idp.example.test/sso?"
            + urlencode({"RelayState": return_to})
        )

    def process_response(self):
        return None

    def get_errors(self):
        return list(type(self).errors)

    def get_last_error_reason(self):
        return type(self).last_error_reason

    def is_authenticated(self):
        return type(self).authenticated

    def get_last_response_xml(self):
        return type(self).response_xml

    def get_last_message_id(self):
        return type(self).message_id

    def get_last_assertion_not_on_or_after(self):
        return type(self).assertion_not_on_or_after

    def get_settings(self):
        return FakeMetadataSettings()


class FakeMetadataParser:
    @staticmethod
    def parse_remote(url):
        return {"idp": {"entityId": url}}

    @staticmethod
    def merge_settings(settings, idp_data):
        merged = dict(settings)
        merged.update(idp_data)
        return merged


class SAMLProviderTest(AsyncHTTPTestCase):
    def setUp(self):
        FakeEtree.reset()
        FakeSAMLAuth.reset()
        self.patchers = [
            mock.patch.object(saml_provider_module, "etree", FakeEtree),
            mock.patch.object(
                saml_provider_module, "OneLogin_Saml2_Auth", FakeSAMLAuth
            ),
            mock.patch.object(
                saml_provider_module,
                "OneLogin_Saml2_IdPMetadataParser",
                FakeMetadataParser,
            ),
        ]
        for patcher in self.patchers:
            patcher.start()
        super().setUp()

    def tearDown(self):
        try:
            super().tearDown()
        finally:
            for patcher in reversed(self.patchers):
                patcher.stop()

    def get_app(self):
        self.hub = build_auth_hub(
            extra_config={
                "AuthHub": {
                    "provider_class": "single_auth_saml.provider.SAMLProvider",
                    "public_base_url": "https://auth.example.test",
                },
                "SAMLProvider": {
                    "saml_settings": {
                        "sp": {
                            "NameIDFormat": (
                                "urn:oasis:names:tc:SAML:1.1:nameid-format:"
                                "unspecified"
                            )
                        }
                    },
                    "xpath_username_location": "//saml:NameID/text()",
                },
            }
        )
        return self.hub.tornado_app

    def fetch_login(self, return_url):
        return self.fetch(
            f"/login?return-url={quote(return_url, safe='')}",
            follow_redirects=False,
        )

    def make_return_url(self, actual_return_url, extra_query=None):
        return make_signed_return_url(self.hub, actual_return_url, extra_query)

    def decode_auth_cookie(self, response):
        cookie = SimpleCookie()
        cookie.load(response.headers["Set-Cookie"])
        morsel = cookie[self.hub.auth_token_name]
        decoded = decode_signed_value(
            self.hub.cookie_secret,
            self.hub.auth_token_name,
            morsel.value,
        )
        return json.loads(decoded.decode("utf-8"))

    def test_login_redirect_round_trips_login_state_in_relay_state(self):
        return_url = self.make_return_url(
            "https://hub.example.test/jupyter/hub/external-login"
        )
        response = self.fetch_login(return_url)
        self.assertEqual(response.code, 302)

        redirect_target = urlparse(response.headers["Location"])
        relay_state = parse_qs(redirect_target.query)["RelayState"][0]
        self.assertEqual(relay_state, FakeSAMLAuth.last_login_return_to)
        self.assertEqual(
            FakeSAMLAuth.last_settings["sp"]["entityId"],
            "https://auth.example.test/auth/metadata",
        )
        self.assertEqual(
            FakeSAMLAuth.last_settings["sp"]["assertionConsumerService"]["url"],
            "https://auth.example.test/auth/callback",
        )

    def test_callback_extracts_username_and_finishes_login(self):
        actual_return_url = "https://hub.example.test/jupyter/hub/external-login"
        return_url = self.make_return_url(actual_return_url, {"next": "/lab"})
        login_response = self.fetch_login(return_url)
        relay_state = parse_qs(urlparse(login_response.headers["Location"]).query)[
            "RelayState"
        ][0]

        response = self.fetch(
            "/auth/callback",
            method="POST",
            body=urlencode({"RelayState": relay_state}),
            follow_redirects=False,
        )
        self.assertEqual(response.code, 302)
        self.assertEqual(
            response.headers["Location"],
            "https://hub.example.test/jupyter/hub/external-login?next=%2Flab",
        )
        self.assertEqual(
            self.decode_auth_cookie(response),
            {"username": "alice", "return_url": actual_return_url},
        )
        self.assertEqual(FakeEtree.last_xpath, "//saml:NameID/text()")
        self.assertEqual(
            FakeEtree.last_namespaces,
            self.hub.provider.saml_namespace,
        )

        cookie = SimpleCookie()
        cookie.load(response.headers["Set-Cookie"])
        self.assertEqual(
            cookie[self.hub.auth_token_name]["domain"],
            "hub.example.test",
        )

    def test_metadata_endpoint_returns_sp_metadata(self):
        response = self.fetch("/auth/metadata")
        self.assertEqual(response.code, 200)
        self.assertIn("text/xml", response.headers["Content-Type"])
        self.assertEqual(response.body.decode("utf-8"), "<EntityDescriptor />")

    def test_unauthenticated_saml_response_is_rejected(self):
        return_url = self.make_return_url(
            "https://hub.example.test/jupyter/hub/external-login"
        )
        login_response = self.fetch_login(return_url)
        relay_state = parse_qs(urlparse(login_response.headers["Location"]).query)[
            "RelayState"
        ][0]
        FakeSAMLAuth.authenticated = False

        response = self.fetch(
            "/auth/callback",
            method="POST",
            body=urlencode({"RelayState": relay_state}),
            follow_redirects=False,
        )
        self.assertEqual(response.code, 403)

    def test_replayed_saml_message_is_rejected(self):
        return_url = self.make_return_url(
            "https://hub.example.test/jupyter/hub/external-login"
        )
        login_response = self.fetch_login(return_url)
        relay_state = parse_qs(urlparse(login_response.headers["Location"]).query)[
            "RelayState"
        ][0]

        first_response = self.fetch(
            "/auth/callback",
            method="POST",
            body=urlencode({"RelayState": relay_state}),
            follow_redirects=False,
        )
        self.assertEqual(first_response.code, 302)

        second_response = self.fetch(
            "/auth/callback",
            method="POST",
            body=urlencode({"RelayState": relay_state}),
            follow_redirects=False,
        )
        self.assertEqual(second_response.code, 403)
