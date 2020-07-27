from tornado import web
from tornado.ioloop import IOLoop
from tornado.log import app_log, access_log, gen_log
import tornado.httpserver
import os
import logging

from traitlets.config import Application, catch_config_error

from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser

from traitlets import List, Bool, Integer, Set, Unicode, Dict, Any, default, observe, Instance, Float, validate, Bytes, Type
from .handlers import SAMLLogin, SAMLMetadataHandler, Template404, HealthCheckHandler

from .utils import url_path_join

class AuthHub(Application):

    aliases = {
        'log_level': 'AuthHub.log_level',
        'f': 'AuthHub.config_file',
        'config': 'AuthHub.config_file',
        'port': 'AuthHub.port'
    }

    flags = {
        'debug': (
            {'Application': {'log_level': logging.DEBUG}},
            "set log level to logging.DEBUG (maximize logging output)",
    ),
        'generate-config': (
            {'AuthHub': {'generate_config': True}},
            "generate default config file",
        )
    }

    generate_config = Bool(False, help="Generate default config file").tag(config=True)

    config_file = Unicode('authhub_config.py', help="The config file to load").tag(
        config=True
    )

    cookie_secret = Bytes(
        help="""The cookie secret to use to encrypt cookies.
        Loaded from the AUTH_COOKIE_SECRET env variable by default.
        Should be exactly 256 bits (32 bytes).
        """
    ).tag(config=True, env='AUTH_COOKIE_SECRET')

    port = Integer(default_value=8888, help="Port that server will listen on.").tag(config=True)

    saml_settings = Dict(
        help="""
        This is a nested dictionary of settings for the python3-saml toolkit.
        """,
        config=True
    )

    saml_namespace = Dict(
        default_value={ 
            'ds'   : 'http://www.w3.org/2000/09/xmldsig#', 
            'md'   : 'urn:oasis:names:tc:SAML:2.0:metadata', 
            'saml' : 'urn:oasis:names:tc:SAML:2.0:assertion', 
            'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol' 
            },
        help="""
        The namespace for the SAML xml.
        """,
        config=True
    )

    xpath_username_location = Unicode(
        default_value='//saml:NameID/text()',
        config=True,
        help="""
        This is the xpath to the username location. The namespace is that given
        in saml_namespace.
        """
    )

    auto_IdP_metadata = Unicode(
        default_value=None,
        allow_none=True,
        help="""
        The url to download the IdP metadata. If None, then assume it is manually supplied.
        """,
        config=True
    )

    metadata_url = Unicode(
        default_value=r'/Shibboleth.sso/Metadata',
        help=
        """
        The sub-url where the IdP will look for the metadata.
        """,
        config=True
    )

    @default('log_level')
    def _log_level_default(self):
        return logging.INFO

    @default('log_datefmt')
    def _log_datefmt_default(self):
        """Exclude date from default date format"""
        return "%Y-%m-%d %H:%M:%S"

    @default('log_format')
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
            answer = ''

            def ask():
                prompt = "Overwrite %s with default config? [y/N]" % self.config_file
                try:
                    return input(prompt).lower() or 'n'
                except KeyboardInterrupt:
                    print('')  # empty line
                    return 'n'

            answer = ask()
            while not answer.startswith(('y', 'n')):
                print("Please answer 'yes' or 'no'")
                answer = ask()
            if answer.startswith('n'):
                return

        config_text = self.generate_config_file()
        if isinstance(config_text, bytes):
            config_text = config_text.decode('utf8')
        print("Writing default config to: %s" % self.config_file)
        with open(self.config_file, mode='w') as f:
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
        if self.auto_IdP_metadata:
            self.log.info("Getting the IdP metadata.")
            idp_data = OneLogin_Saml2_IdPMetadataParser.parse_remote(self.auto_IdP_metadata)
            self.saml_settings = OneLogin_Saml2_IdPMetadataParser.merge_settings(self.saml_settings, idp_data)

        self.init_logging()
        self.init_handlers()
        self.init_tornado_settings()
        self.init_tornado()
    
    def init_handlers(self):
        self.log.info("Initializing handlers.")
        self.handlers = [
                         (r"/saml_login", SAMLLogin),
                         (self.metadata_url, SAMLMetadataHandler),
                         (r'/health$', HealthCheckHandler),
                         (r'(.*)', Template404)
                         ]

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
            config = self.config,
            log=self.log,
            cookie_secret = self.cookie_secret,
            saml_settings = self.saml_settings,
            saml_namespace = self.saml_namespace,
            xpath_username_location = self.xpath_username_location,
            app = self
        )

    def init_tornado(self):
        self.log.info("Initializing tornado app.")
        self.tornado_app = web.Application(handlers=self.handlers, **self.tornado_settings)

    def start(self):

        self.log.info("Starting the app.")
        if self.generate_config:
            self.write_config_file()
            return

        http_server = tornado.httpserver.HTTPServer(self.tornado_app)
        http_server.listen(self.port)
        try:
            IOLoop.instance().start()
        except KeyboardInterrupt:
            IOLoop.instance().stop()

def main(argv=None):
    app = AuthHub()
    app.initialize()
    app.start()

if __name__ == "__main__":
    main()