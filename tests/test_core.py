import json
import unittest
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, quote, urlparse

from tornado.testing import AsyncHTTPTestCase
from tornado.web import decode_signed_value
from traitlets import TraitError

from SingleAuthServer.app import AuthHub
from tests.support import COOKIE_SECRET, build_auth_hub, make_signed_return_url


class CoreLoginFlowTest(AsyncHTTPTestCase):
    def get_app(self):
        self.hub = build_auth_hub()
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
        return json.loads(decoded.decode("utf-8")), response.headers["Set-Cookie"]

    def test_missing_return_url_is_rejected(self):
        response = self.fetch("/login", follow_redirects=False)
        self.assertEqual(response.code, 400)

    def test_relative_return_url_is_rejected(self):
        response = self.fetch(
            f"/login?return-url={quote('/hub/external-login', safe='')}",
            follow_redirects=False,
        )
        self.assertEqual(response.code, 400)

    def test_login_flow_sets_cookie_and_redirects_to_verified_return_url(self):
        actual_return_url = "https://hub.example.test/jupyter/hub/external-login"
        return_url = self.make_return_url(actual_return_url, {"next": "/lab"})
        login_response = self.fetch_login(return_url)
        self.assertEqual(login_response.code, 302)

        provider_redirect = urlparse(login_response.headers["Location"])
        callback_path = provider_redirect.path
        if provider_redirect.query:
            callback_path = f"{callback_path}?{provider_redirect.query}"

        callback_response = self.fetch(callback_path, follow_redirects=False)
        self.assertEqual(callback_response.code, 302)
        self.assertEqual(
            callback_response.headers["Location"],
            "https://hub.example.test/jupyter/hub/external-login?next=%2Flab",
        )

        payload, cookie_header = self.decode_auth_cookie(callback_response)
        self.assertEqual(
            payload,
            {"username": "alice", "return_url": actual_return_url},
        )
        self.assertIn("Path=/jupyter/hub/external-login", cookie_header)
        self.assertIn("Secure", cookie_header)
        self.assertIn("Domain=hub.example.test", cookie_header)

    def test_replayed_login_state_is_rejected(self):
        """A login state is single-use, even inside its TTL.

        Signature and TTL checks alone let a captured state be submitted twice.
        The SAML provider catches that via the assertion message ID, but that is
        provider-specific; this must hold for every provider.
        """
        return_url = self.make_return_url(
            "https://hub.example.test/jupyter/hub/external-login"
        )
        login_response = self.fetch_login(return_url)
        provider_redirect = urlparse(login_response.headers["Location"])
        callback_path = f"{provider_redirect.path}?{provider_redirect.query}"

        first = self.fetch(callback_path, follow_redirects=False)
        self.assertEqual(first.code, 302, "first redemption should succeed")

        replay = self.fetch(callback_path, follow_redirects=False)
        self.assertEqual(replay.code, 403, "replayed login state must be rejected")

    def test_replayed_login_state_rejected_under_a_different_username(self):
        """The nonce check must not be keyed on the username.

        Providers that take the username from the caller (rather than from a
        signed assertion) would otherwise let an attacker replay one login state
        under a second name and land in a different account.
        """
        return_url = self.make_return_url(
            "https://hub.example.test/jupyter/hub/external-login"
        )
        login_response = self.fetch_login(return_url)
        provider_redirect = urlparse(login_response.headers["Location"])
        state_token = parse_qs(provider_redirect.query)["state"][0]

        def redeem(username):
            return self.fetch(
                f"{provider_redirect.path}"
                f"?state={quote(state_token, safe='')}&username={username}",
                follow_redirects=False,
            )

        self.assertEqual(redeem("alice").code, 302)
        self.assertEqual(redeem("mallory").code, 403)

    def test_expired_nonces_are_pruned(self):
        """The nonce table is bounded by the TTL, not by login volume."""
        from SingleAuthServer.orm import LoginStateNonce

        with self.hub.make_session() as session:
            session.add(LoginStateNonce(nonce="stale-entry", expires_at=1))

        # Any subsequent redemption triggers the prune.
        return_url = self.make_return_url(
            "https://hub.example.test/jupyter/hub/external-login"
        )
        login_response = self.fetch_login(return_url)
        provider_redirect = urlparse(login_response.headers["Location"])
        self.fetch(
            f"{provider_redirect.path}?{provider_redirect.query}",
            follow_redirects=False,
        )

        with self.hub.make_session() as session:
            remaining = (
                session.query(LoginStateNonce)
                .filter(LoginStateNonce.nonce == "stale-entry")
                .first()
            )
        self.assertIsNone(remaining, "expired nonce should have been pruned")

    def test_tampered_login_state_is_rejected(self):
        return_url = self.make_return_url(
            "https://hub.example.test/jupyter/hub/external-login"
        )
        login_response = self.fetch_login(return_url)
        provider_redirect = urlparse(login_response.headers["Location"])
        state_token = parse_qs(provider_redirect.query)["state"][0]
        tampered = state_token[:-1] + ("a" if state_token[-1] != "a" else "b")

        response = self.fetch(
            f"{provider_redirect.path}?state={quote(tampered, safe='')}&username=alice",
            follow_redirects=False,
        )
        self.assertEqual(response.code, 403)

    def test_expired_login_state_is_rejected(self):
        return_url = self.make_return_url(
            "https://hub.example.test/jupyter/hub/external-login"
        )
        login_response = self.fetch_login(return_url)
        provider_redirect = urlparse(login_response.headers["Location"])
        state_token = parse_qs(provider_redirect.query)["state"][0]
        self.hub.login_state_ttl = -1

        response = self.fetch(
            f"{provider_redirect.path}?state={quote(state_token, safe='')}&username=alice",
            follow_redirects=False,
        )
        self.assertEqual(response.code, 403)

    def test_cookie_domain_can_be_configured(self):
        return_url = self.make_return_url(
            "https://hub.example.test/jupyter/hub/external-login"
        )
        login_response = self.fetch_login(return_url)
        provider_redirect = urlparse(login_response.headers["Location"])
        self.hub.auth_token_cookie_domain = "example.test"

        callback_path = provider_redirect.path
        if provider_redirect.query:
            callback_path = f"{callback_path}?{provider_redirect.query}"

        callback_response = self.fetch(callback_path, follow_redirects=False)
        self.assertEqual(callback_response.code, 302)
        self.assertIn("Domain=example.test", callback_response.headers["Set-Cookie"])

    def test_missing_signed_return_url_is_rejected(self):
        return_url = "https://hub.example.test/jupyter/hub/external-login"
        login_response = self.fetch_login(return_url)
        provider_redirect = urlparse(login_response.headers["Location"])

        callback_path = provider_redirect.path
        if provider_redirect.query:
            callback_path = f"{callback_path}?{provider_redirect.query}"

        callback_response = self.fetch(callback_path, follow_redirects=False)
        self.assertEqual(callback_response.code, 400)

    def test_tampered_signed_return_url_is_rejected(self):
        actual_return_url = "https://hub.example.test/jupyter/hub/external-login"
        other_return_url = "https://hub.example.test/jupyter/hub/other-login"
        return_url = make_signed_return_url(self.hub, other_return_url)
        return_url = return_url.replace(other_return_url, actual_return_url, 1)

        login_response = self.fetch_login(return_url)
        provider_redirect = urlparse(login_response.headers["Location"])

        callback_path = provider_redirect.path
        if provider_redirect.query:
            callback_path = f"{callback_path}?{provider_redirect.query}"

        callback_response = self.fetch(callback_path, follow_redirects=False)
        self.assertEqual(callback_response.code, 403)


class ProviderValidationTest(unittest.TestCase):
    def test_invalid_provider_import_raises_trait_error(self):
        hub = AuthHub()
        hub.cookie_secret = COOKIE_SECRET
        hub.provider_class = "does.not.exist.Provider"
        hub.public_base_url = "https://auth.example.test"
        hub.init_logging()

        with self.assertRaises(TraitError):
            hub.init_provider()

    def test_provider_must_inherit_base_auth_provider(self):
        hub = AuthHub()
        hub.cookie_secret = COOKIE_SECRET
        hub.provider_class = "tests.support.NotAProvider"
        hub.public_base_url = "https://auth.example.test"
        hub.init_logging()

        with self.assertRaises(TraitError):
            hub.init_provider()

    def test_provider_validation_errors_surface_at_startup(self):
        hub = AuthHub()
        hub.cookie_secret = COOKIE_SECRET
        hub.provider_class = "tests.support.BrokenProvider"
        hub.public_base_url = "https://auth.example.test"
        hub.init_logging()

        with self.assertRaises(TraitError):
            hub.init_provider()

    def test_public_base_url_must_be_absolute(self):
        hub = AuthHub()
        with self.assertRaises(TraitError):
            hub.public_base_url = "/relative/path"
