from tornado import web
from tornado.log import app_log

from ..provider import LoginRequestContext


class BaseHandler(web.RequestHandler):
    @property
    def log(self):
        return self.settings.get("log", app_log)

    @property
    def auth_hub(self):
        return self.settings["app"]

    @property
    def provider(self):
        return self.settings["provider"]


class Template404(BaseHandler):
    async def prepare(self):
        super().prepare()
        raise web.HTTPError(404)


class LoginHandler(BaseHandler):
    def get(self):
        return_url = self.get_argument("return-url", "")
        if not return_url:
            self.log.warning("Attempted login without a return-url.")
            raise web.HTTPError(400, log_message="Missing required return-url.")

        try:
            self.auth_hub.validate_return_url(return_url)
        except ValueError as exc:
            self.log.warning("Invalid return-url %r: %s", return_url, exc)
            raise web.HTTPError(400, log_message=str(exc))

        state_token = self.auth_hub.issue_login_state(return_url)
        redirect_target = self.provider.begin_login(
            LoginRequestContext(
                return_url=return_url,
                state_token=state_token,
                public_base_url=self.auth_hub.public_base_url,
                handler=self,
            )
        )

        if not redirect_target:
            raise web.HTTPError(500, log_message="Provider returned no redirect.")

        self.redirect(redirect_target)


class HealthCheckHandler(BaseHandler):
    def get(self, *args):
        self.finish()
