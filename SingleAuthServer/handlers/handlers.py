from tornado import web
from tornado.httputil import url_concat, split_host_and_port
from urllib.parse import urlparse, parse_qs, parse_qsl, urlunparse, urlencode
from tornado.log import app_log
import time
from copy import deepcopy

from tornado_sqlalchemy import as_future, SessionMixin, SQLAlchemy

from lxml import etree

import json

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings

from ..utils import url_path_join
from ..orm import User

class BaseHandler(SessionMixin, web.RequestHandler):
    @property
    def log(self):
        return self.settings.get('log', app_log)

    @property
    def db(self):
        return self.settings.get('db')

class Template404(BaseHandler):
    """Render our 404 template"""

    async def prepare(self):
        # await super().prepare()
        super().prepare()
        raise web.HTTPError(404)

class SAMLBaseHandler(BaseHandler):

    @property
    def saml_namespace(self):
        return self.settings.get('saml_namespace', { 
            'ds'   : 'http://www.w3.org/2000/09/xmldsig#', 
            'md'   : 'urn:oasis:names:tc:SAML:2.0:metadata', 
            'saml' : 'urn:oasis:names:tc:SAML:2.0:assertion', 
            'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol' 
            })

    @property
    def xpath_username_location(self):
        return self.settings.get('xpath_username_location', '//saml:NameID/text()')

    @property
    def saml_custom_base_path(self):
        return self.settings.get('saml_custom_base_path')

    @property
    def saml_settings(self):
        return self.settings.get('saml_settings')

    @property
    def force_https(self):
        return self.settings.get('force_https')

    # @property
    # def secure_token_name(self):
    #     return self.settings.get('secure_token_name')

    auth_token_name = 'auth-token'

    # @property
    # def separation_character(self):
    #     return self.settings.get('separation_character', '^')

    def prepare_tornado_request(self, request):

        dataDict = {}
        for key in request.arguments:
            dataDict[key] = request.arguments[key][0].decode('utf-8')

        result = {
            'https': 'on' if request == 'https' else 'off',
            'http_host': split_host_and_port(request.host)[0],
            'script_name': request.path,
            'server_port': split_host_and_port(request.host)[1],
            'get_data': dataDict,
            'post_data': dataDict,
            'query_string': request.query
        }

        if self.force_https:
            result['https'] = self.force_https

        return result

    def init_saml_auth(self, req):
        auth = OneLogin_Saml2_Auth(req, self.saml_settings, custom_base_path=self.saml_custom_base_path)
        return auth


class SAMLLogin(SAMLBaseHandler):

    def get(self):
        req = self.prepare_tornado_request(self.request)
        auth = self.init_saml_auth(req)
        # error_reason = None
        # errors = []
        if not self.get_argument('return-url', ''):
            self.log.warning("Attempted login without a return-url.")
            raise web.HTTPError(400)
        redirect_url = self.get_argument('return-url')

        return self.redirect(auth.login(redirect_url))

    def post(self):
        req = self.prepare_tornado_request(self.request)
        auth = self.init_saml_auth(req)

        self.log.debug("Debug setting is: %r" % str(auth.get_settings().is_debug_active()))
        self.log.debug("Strict mode is active: %r" % str(auth.get_settings().is_strict()))

        auth.process_response()
        errors = auth.get_errors()
        if errors:
            self.log.warning("Errors are:\n" + "\n".join(errors))
            self.log.warning("Last error reason is: %r" % auth.get_last_error_reason())

        if not auth.is_authenticated():
            self.log.warning("Unauthorized login attempt.")
            raise web.HTTPError(403, log_message="Unauthorized login attempt!")

        response_xml = auth.get_last_response_xml()
        tree = etree.fromstring(response_xml)

        username = tree.xpath(self.xpath_username_location, namespaces=self.saml_namespace)[0]
        if not username:
            self.log.warning("SAML is valid, but it does not contain a username at the expected place.")
            raise web.HTTPError(404)

        message_id = auth.get_last_message_id()

        with self.make_session() as session:
            user = session.query(User).filter(User.username == username).first()
            if user is None:
                self.log.info("User %r is not in the database. Adding..." % username)
                user = User(username=username)
                session.add(user)
            
            self.log.debug("User auth state is: %r" % user.auth_state)

            if isinstance(user.auth_state, dict):
                message_history = user.auth_state.get('saml_message_history', {})

                if message_id in message_history:
                    self.log.warning("Replay attack on user %r. Stop authentication.", username)
                    raise web.HTTPError(403, log_message="Invalid login credentials.")

            else:
                user.auth_state = {}

            self.log.debug("Adding message id %r with expiration %r to auth_state." % (message_id, auth.get_last_assertion_not_on_or_after()))
            # This is because you cannot update JSON fields in place in SQLAlchemy.
            # It needs to be a new dictionary, hence the deepcopy.
            auth_state = deepcopy(user.auth_state)
            saml_message_history = auth_state.setdefault('saml_message_history', {})
            saml_message_history[message_id] = auth.get_last_assertion_not_on_or_after()

            auth_state['saml_message_history'] = self.remove_expired_message_ids(saml_message_history)

            self.log.debug("Attempting to write auth_state of: %r" % auth_state)
            user.auth_state = auth_state

        if 'RelayState' not in self.request.arguments:
            self.log.warning("RelayState not in url query parameters.")
            raise web.HTTPError(400)

        self.log.info("User %r has successfully SAML authenticated. Forwarding %r." % (username, self.auth_token_name))

        # This is to get the unique ID for the server I'm interacting with.
        return_url = self.request.arguments['RelayState'][0].decode('utf-8')
        parsed_url = list(urlparse(return_url))
        qs = parse_qs(parsed_url[4], keep_blank_values=True)

        required_args = ['unique-id']
        for arg in required_args:
            if arg not in qs.keys():
                self.log.warning("Authentication failed. Missing required return URL argument %r" % arg)
                raise web.HTTPError(400)

        unique_id = qs.pop('unique-id', '')[0]
        
        parsed_url[4] = urlencode(qs, doseq=True)

        token_data = {'username': username, 'unique_id': unique_id}
        token_data = json.dumps(token_data).encode('utf-8')

        # Here we create a signed token that is the combination of the username and unique ID.
        return_token = self.create_signed_value(name=self.auth_token_name, value=token_data)

        # Construct the final return url.
        return_url = urlunparse(parsed_url)
        return_url = url_concat(return_url, {self.auth_token_name: return_token})

        self.redirect(return_url)

    def remove_expired_message_ids(self, message_history):
        now = time.time()
        self.log.debug("Removing expired message IDs. Current time is %r" % now)
        keys = [k for k, v in message_history.items() if not isinstance(v, int) or v < now]
        for k in keys:
            self.log.debug("Removing expired message with id %r and expiration time %r" % (k, message_history[k]))
            message_history.pop(k)
        return message_history

class SAMLMetadataHandler(SAMLBaseHandler):
    def get(self):
        req = self.prepare_tornado_request(self.request)
        auth = self.init_saml_auth(req)
        saml_settings = auth.get_settings()
        metadata = saml_settings.get_sp_metadata()
        errors = saml_settings.validate_metadata(metadata)
        self.log.info("Metadata requested.")

        if len(errors) == 0:
            self.set_header('Content-Type', 'text/xml')
            self.write(metadata)
        else:
            self.write(', '.join(errors))

class HealthCheckHandler(BaseHandler):
    """Answer to health check"""

    def get(self, *args):
        self.finish()