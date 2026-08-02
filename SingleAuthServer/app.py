import asyncio
import binascii
from contextlib import contextmanager
import json
import logging
import os
import signal
import time
import uuid
from functools import partial
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import tornado.httpserver
from tornado import web
from tornado.ioloop import IOLoop
from tornado.log import access_log, app_log, gen_log
from traitlets import Bool, Bytes, Integer, Unicode, default, observe, validate
from traitlets import TraitError
from traitlets.config import Application, catch_config_error

from sqlalchemy.exc import IntegrityError

from .handlers import HealthCheckHandler, LoginHandler, Template404
from .orm import LoginStateNonce, create_session_factory
from .provider import load_provider_class
from .utils import normalize_public_base_url, validate_absolute_http_url

COOKIE_SECRET_BYTES = (
    32  # the number of bytes to use when generating new cookie secrets
)

_mswindows = os.name == "nt"

TORNADO_SHUTDOWN_WAIT=10

class AuthHub(Application):

    aliases = {
        "log_level": "AuthHub.log_level",
        "f": "AuthHub.config_file",
        "config": "AuthHub.config_file",
        "port": "AuthHub.port",
        "provider": "AuthHub.provider_class",
    }

    flags = {
        "debug": (
            {"Application": {"log_level": logging.DEBUG}},
            "set log level to logging.DEBUG (maximize logging output)",
        ),
        "generate-config": (
            {"AuthHub": {"generate_config": True}},
            "generate default config file",
        ),
    }

    generate_config = Bool(False, help="Generate default config file").tag(config=True)

    config_file = Unicode("authhub_config.py", help="The config file to load").tag(
        config=True
    )

    cookie_secret = Bytes(
        help="""The cookie secret to use to encrypt cookies.
        Loaded from the AUTH_COOKIE_SECRET env variable by default.
        Should be exactly 256 bits (32 bytes).
        """
    ).tag(config=True, env='AUTH_COOKIE_SECRET')

    @observe("cookie_secret")
    def _cookie_secret_check(self, change):
        secret = change.new
        if len(secret) > COOKIE_SECRET_BYTES:
            self.log.warning(
                "Cookie secret is %i bytes.  It should be %i.",
                len(secret),
                COOKIE_SECRET_BYTES,
            )

    cookie_secret_file = Unicode(
        "authhub_cookie_secret", help="""File in which to store the cookie secret."""
    ).tag(config=True)

    port = Integer(default_value=8888, help="Port that server will listen on.").tag(config=True)

    db_url = Unicode(
        default_value="sqlite:///authhub.sqlite",
        help="Database URL used for persisted auth state and replay protection.",
    ).tag(config=True)

    provider_class = Unicode(
        default_value="",
        help="""
        Import path for the configured authentication provider.
        Example: `single_auth_saml.provider.SAMLProvider`.
        """,
    ).tag(config=True)

    public_base_url = Unicode(
        default_value="",
        help="""
        Public base URL for this auth service, including any path prefix.
        Used when providers need externally visible callback URLs.
        """,
    ).tag(config=True)

    auth_token_name = Unicode(
        default_value="auth-token",
        help="""
        Secure cookie name used for the downstream authenticator contract.
        """,
    ).tag(config=True)

    login_state_name = Unicode(
        default_value="login-state",
        help="""
        Signing namespace used for short-lived login state tokens.
        """,
    ).tag(config=True)

    login_state_ttl = Integer(
        default_value=300,
        help="Maximum age of a login state token in seconds.",
    ).tag(config=True)

    signed_return_url_name = Unicode(
        default_value="signed-return-url",
        help="Signed query argument used to prove the downstream return URL.",
    ).tag(config=True)

    auth_token_cookie_domain = Unicode(
        default_value=None,
        allow_none=True,
        help="""
        Optional domain attribute for the auth-token cookie. If omitted, the
        cookie is host-only.
        """,
    ).tag(config=True)

    @validate("public_base_url")
    def _validate_public_base_url(self, proposal):
        value = proposal["value"]
        if not value:
            return value
        try:
            return normalize_public_base_url(value)
        except ValueError as exc:
            raise TraitError(str(exc)) from exc

    @validate("auth_token_cookie_domain")
    def _validate_auth_token_cookie_domain(self, proposal):
        value = proposal["value"]
        if value and ":" in value:
            raise TraitError(
                "auth_token_cookie_domain must not include a port number."
            )
        return value

    @default("log_level")
    def _log_level_default(self):
        return logging.INFO

    @default("log_datefmt")
    def _log_datefmt_default(self):
        """Exclude date from default date format"""
        return "%Y-%m-%d %H:%M:%S"

    @default("log_format")
    def _log_format_default(self):
        """override default log format to include time"""
        return "[%(levelname)1.1s %(asctime)s.%(msecs).03d %(name)s %(module)s:%(lineno)d] %(message)s"

    def write_config_file(self):
        """Write our default config to a .py config file"""
        config_file_dir = os.path.dirname(os.path.abspath(self.config_file))
        if not os.path.isdir(config_file_dir):
            self.exit(
                "{} does not exist. The destination directory must exist before generating config file.".format(
                    config_file_dir
                )
            )
        if os.path.exists(self.config_file):
            answer = ""

            def ask():
                prompt = "Overwrite %s with default config? [y/N]" % self.config_file
                try:
                    return input(prompt).lower() or "n"
                except KeyboardInterrupt:
                    print("")  # empty line
                    return "n"

            answer = ask()
            while not answer.startswith(("y", "n")):
                print("Please answer 'yes' or 'no'")
                answer = ask()
            if answer.startswith("n"):
                return

        config_text = self.generate_config_file()
        if isinstance(config_text, bytes):
            config_text = config_text.decode("utf8")
        print("Writing default config to: %s" % self.config_file)
        with open(self.config_file, mode="w") as f:
            f.write(config_text)

    @catch_config_error
    def initialize(self, *args, **kwargs):
        super().initialize(*args, **kwargs)
        self.log.info("Initializing AuthHub")
        self.parse_command_line(*args, **kwargs)
        if self.generate_config:
            return

        self.log.info("Loading config")
        self.load_config_file(self.config_file)

        self.init_logging()
        self.init_db()
        self.init_secrets()
        self.init_provider()
        self.init_handlers()
        self.init_tornado_settings()
        self.init_tornado()

    def validate_runtime_configuration(self):
        if not self.provider_class:
            raise TraitError("provider_class must be configured.")
        if not self.public_base_url:
            raise TraitError("public_base_url must be configured.")
        self.public_base_url = normalize_public_base_url(self.public_base_url)

    def init_provider(self):
        self.log.info("Initializing provider.")
        self.validate_runtime_configuration()
        provider_class = load_provider_class(self.provider_class)
        self.provider = provider_class(self)
        self.provider.validate_configuration()

    def init_db(self):
        self.log.info("Initializing the database.")
        self.db_engine, self.db_session_factory = create_session_factory(self.db_url)

    @contextmanager
    def make_session(self):
        session = self.db_session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def init_handlers(self):
        self.log.info("Initializing handlers.")
        self.handlers = [(r"/login", LoginHandler)]
        self.handlers.extend(self.provider.get_handlers())
        self.handlers.extend(
            [
                (r"/health$", HealthCheckHandler),
                (r"(.*)", Template404),
            ]
        )

    def init_logging(self):
        self.log.info("Initializing loggers.")
        # This prevents double log messages because tornado use a root logger that
        # self.log is a child of. The logging module dipatches log messages to a log
        # and all of its ancenstors until propagate is set to False.
        self.log.propagate = False

        # disable curl debug, which is TOO MUCH
        logging.getLogger('tornado.curl_httpclient').setLevel(
            max(self.log_level, logging.INFO)
        )

        # hook up tornado 3's loggers to our app handlers
        for log in (app_log, access_log, gen_log):
            # ensure all log statements identify the application they come from
            log.name = self.log.name
        logger = logging.getLogger('tornado')
        logger.propagate = True
        logger.parent = self.log
        logger.setLevel(self.log.level)

    def init_tornado_settings(self):
        self.log.info("Initializing tornado settings.")
        self.tornado_settings = dict(
            config=self.config,
            log=self.log,
            cookie_secret=self.cookie_secret,
            app=self,
            provider=self.provider,
        )

    def init_tornado(self):
        self.log.info("Initializing tornado app.")
        self.tornado_app = web.Application(handlers=self.handlers, **self.tornado_settings)

    def validate_return_url(self, return_url):
        validate_absolute_http_url(return_url, label="return-url")
        return return_url

    def issue_login_state(self, return_url):
        payload = json.dumps(
            {
                "return_url": return_url,
                "iat": int(time.time()),
                "nonce": uuid.uuid4().hex,
            }
        ).encode("utf-8")
        return web.create_signed_value(
            self.cookie_secret,
            self.login_state_name,
            payload,
        ).decode("utf-8")

    def decode_login_state(self, state_token):
        decoded = web.decode_signed_value(
            self.cookie_secret,
            self.login_state_name,
            state_token,
        )
        if decoded is None:
            raise web.HTTPError(403, log_message="Invalid login state.")

        try:
            payload = json.loads(decoded.decode("utf-8"))
        except (TypeError, ValueError, UnicodeDecodeError) as exc:
            raise web.HTTPError(403, log_message="Invalid login state.") from exc

        return_url = payload.get("return_url")
        issued_at = payload.get("iat")
        nonce = payload.get("nonce")

        if not isinstance(return_url, str) or not isinstance(nonce, str):
            raise web.HTTPError(403, log_message="Invalid login state.")

        try:
            issued_at = int(issued_at)
        except (TypeError, ValueError) as exc:
            raise web.HTTPError(403, log_message="Invalid login state.") from exc

        if int(time.time()) > issued_at + self.login_state_ttl:
            raise web.HTTPError(403, log_message="Expired login state.")

        try:
            self.validate_return_url(return_url)
        except ValueError as exc:
            raise web.HTTPError(403, log_message=str(exc)) from exc

        self.consume_login_state_nonce(nonce, issued_at + self.login_state_ttl)

        return payload

    def consume_login_state_nonce(self, nonce, expires_at):
        """Redeem a login-state nonce exactly once.

        Signature and TTL checks alone do not stop a captured login state from
        being submitted twice inside its TTL window. The SAML provider catches
        that separately via the assertion message ID, but that protection is
        provider-specific — this closes it for every provider.

        Uniqueness is enforced by the primary key rather than a read-then-write,
        so two concurrent redemptions of the same nonce cannot both win.
        """
        now = int(time.time())
        with self.make_session() as session:
            session.query(LoginStateNonce).filter(
                LoginStateNonce.expires_at < now
            ).delete(synchronize_session=False)

            session.add(LoginStateNonce(nonce=nonce, expires_at=expires_at))
            try:
                session.flush()
            except IntegrityError as exc:
                self.log.warning(
                    "Login state nonce %r was already redeemed. "
                    "Rejecting as a replay.",
                    nonce,
                )
                raise web.HTTPError(
                    403, log_message="Replayed login state."
                ) from exc

    def validate_signed_return_url(self, handler, return_url):
        parsed_return_url = urlparse(return_url)
        query_args = parse_qs(parsed_return_url.query, keep_blank_values=True)

        if self.signed_return_url_name not in query_args:
            raise web.HTTPError(
                400,
                log_message=(
                    f"Missing required return URL argument "
                    f"{self.signed_return_url_name!r}."
                ),
            )

        signed_return_url = query_args.pop(self.signed_return_url_name, [""])[0]
        reported_return_url = handler.get_secure_cookie(
            name=self.signed_return_url_name,
            value=signed_return_url,
        )
        if reported_return_url is None:
            raise web.HTTPError(403, log_message="Invalid signed return-url.")

        reported_return_url = reported_return_url.decode("utf-8")
        actual_return_url = urlunparse(
            parsed_return_url._replace(params="", query="", fragment="")
        )

        if actual_return_url != reported_return_url:
            self.log.warning(
                "Actual and reported return URLs differ. Actual URL is %r and "
                "reported return URL is %r",
                actual_return_url,
                reported_return_url,
            )
            raise web.HTTPError(403, log_message="Invalid return-url proof.")

        redirect_return_url = urlunparse(
            parsed_return_url._replace(query=urlencode(query_args, doseq=True))
        )

        return reported_return_url, redirect_return_url, parsed_return_url

    def finalize_login(self, handler, username, state_token):
        if not username:
            raise web.HTTPError(403, log_message="Missing username.")

        payload = self.decode_login_state(state_token)
        return_url = payload["return_url"]
        (
            reported_return_url,
            redirect_return_url,
            parsed_return_url,
        ) = self.validate_signed_return_url(handler, return_url)
        cookie_path = parsed_return_url.path or "/"
        cookie_domain = self.auth_token_cookie_domain or parsed_return_url.hostname

        token_data = json.dumps(
            {"username": username, "return_url": reported_return_url}
        ).encode("utf-8")

        cookie_kwargs = dict(
            name=self.auth_token_name,
            value=token_data,
            expires_days=None,
            path=cookie_path,
            secure=parsed_return_url.scheme == "https",
            httponly=True,
        )
        if cookie_domain:
            cookie_kwargs["domain"] = cookie_domain

        self.log.info("User %r authenticated. Setting %r.", username, self.auth_token_name)
        handler.set_secure_cookie(**cookie_kwargs)
        handler.redirect(redirect_return_url)

    def init_secrets(self):
        trait_name = "cookie_secret"
        trait = self.traits()[trait_name]
        env_name = trait.metadata.get("env")
        secret_file = os.path.abspath(os.path.expanduser(self.cookie_secret_file))
        secret = self.cookie_secret
        secret_from = "config"
        # load priority: 1. config, 2. env, 3. file
        secret_env = os.environ.get(env_name)
        if not secret and secret_env:
            secret_from = "env"
            self.log.info("Loading %s from env[%s]", trait_name, env_name)
            secret = binascii.a2b_hex(secret_env)
        if not secret and os.path.exists(secret_file):
            secret_from = "file"
            self.log.info("Loading %s from %s", trait_name, secret_file)
            try:
                if not _mswindows:  # Windows permissions don't follow POSIX rules
                    perm = os.stat(secret_file).st_mode
                    if perm & 0o07:
                        msg = "cookie_secret_file can be read or written by anybody"
                        raise ValueError(msg)
                with open(secret_file) as f:
                    text_secret = f.read().strip()
                secret = binascii.a2b_hex(text_secret)
            except Exception as e:
                self.log.error(
                    "Refusing to run AuthHub with invalid cookie_secret_file. "
                    "%s error was: %s",
                    secret_file,
                    e,
                )
                self.exit(1)

        if not secret:
            secret_from = "new"
            self.log.debug("Generating new %s", trait_name)
            secret = os.urandom(COOKIE_SECRET_BYTES)

        if secret_file and secret_from == "new":
            # if we generated a new secret, store it in the secret_file
            self.log.info("Writing %s to %s", trait_name, secret_file)
            text_secret = binascii.b2a_hex(secret).decode("ascii")
            with open(secret_file, "w") as f:
                f.write(text_secret)
                f.write("\n")
            if not _mswindows:  # Windows permissions don't follow POSIX rules
                try:
                    os.chmod(secret_file, 0o600)
                except OSError:
                    self.log.warning("Failed to set permissions on %s", secret_file)
        # store the loaded trait value
        self.cookie_secret = secret

    def sig_handler(self, server, sig, frame):
        io_loop = IOLoop.instance()

        def stop_loop(server, deadline):
            now = time.time()

            tasks = [
                t
                for t in asyncio.all_tasks()
                if t is not asyncio.current_task() and not t.done()
            ]
            if now < deadline and len(tasks) > 0:
                self.log.info(f"Awaiting {len(tasks)} pending tasks: {tasks}")
                io_loop.add_timeout(now + 1, stop_loop, server, deadline)
                return

            pending_connection = len(server._connections)
            if now < deadline and pending_connection > 0:
                self.log.info(f"Waiting on {pending_connection} connections to complete.")
                io_loop.add_timeout(now + 1, stop_loop, server, deadline)
            else:
                self.log.info(f"Continuing with {pending_connection} connections open.")
                self.log.info("Stopping IOLoop")
                io_loop.stop()
                self.log.info("Shutdown complete.")

        def shutdown():
            self.log.info(f"Will shutdown in {TORNADO_SHUTDOWN_WAIT} seconds ...")
            try:
                stop_loop(server, time.time() + TORNADO_SHUTDOWN_WAIT)
            except BaseException as e:
                self.log.warning(f"Error trying to shutdown Tornado: {str(e)}")

        logging.warning("Caught signal: %s", sig)
        io_loop.add_callback_from_signal(shutdown)

    def start(self):

        self.log.info("Starting the app.")
        if self.generate_config:
            self.write_config_file()
            return

        http_server = tornado.httpserver.HTTPServer(self.tornado_app)
        http_server.listen(self.port)

        signal.signal(signal.SIGTERM, partial(self.sig_handler, http_server))
        signal.signal(signal.SIGINT, partial(self.sig_handler, http_server))

        IOLoop.instance().start()
        self.log.info("Cleanly shut down the server.")


def main(argv=None):
    app = AuthHub()
    if argv is None:
        app.initialize()
    else:
        app.initialize(argv)
    app.start()

if __name__ == "__main__":
    main()
