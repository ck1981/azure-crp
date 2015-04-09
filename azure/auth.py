# coding:utf-8
import threading
import webbrowser
import logging

import flask
import requests
from oauth2client.client import OAuth2WebServerFlow, AccessTokenCredentials


logger = logging.getLogger(__name__)


AZURE_AUTH_URI_TPL = "https://login.windows.net/{tenant_id}/oauth2/authorize?api-version=1.0"
AZURE_TOKEN_URI_TPL = "https://login.windows.net/{tenant_id}/oauth2/token?api-version=1.0"


USER_AGENT = "Scalr Auth 123"
AUTH_PORT = 7000


class AuthThread(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.code = None
        self.app = flask.Flask(__name__)

        def shutdown():
            do_shutdown = flask.request.environ.get('werkzeug.server.shutdown')
            do_shutdown()


        @self.app.route("/sign-on")
        def sign_on():
            """
            Collect the OAuth code from the response.
            """
            self.code = flask.request.args.get('code')
            if self.code is not None:
                shutdown()
                return flask.make_response("<p>Code: {0}</p><script>window.close()</script>".format(self.code))

            error = flask.request.args.get('error')
            if error is not None:
                print("Error: {0}".format(error))
                print("Description: {0}".format(flask.request.args.get('error_description')))

            return flask.Response(status=400)

    def run(self):
        self.app.run(port=AUTH_PORT)


class AzureApp(object):
    def __init__(self, app_client_id, app_client_secret):
        self.app_client_id = app_client_id
        self.app_client_secret = app_client_secret

    def get_credentials_for_resource(self, tenant_id, resource, **extra):
        # Set up the OAuth auth thread.
        auth_thread = AuthThread()
        auth_thread.start()

        flow = OAuth2WebServerFlow(
            client_id=self.app_client_id,
            client_secret=self.app_client_secret,
            scope='user_impersonation',
            redirect_uri='http://127.0.0.1:{0}/sign-on'.format(AUTH_PORT),

            auth_uri=AZURE_AUTH_URI_TPL.format(tenant_id=tenant_id),
            token_uri=AZURE_TOKEN_URI_TPL.format(tenant_id=tenant_id),

            resource=resource,
            **extra
        )

        auth_uri = flow.step1_get_authorize_url()
        webbrowser.open_new_tab(auth_uri)
        logger.info("Auth URL: %s", auth_uri)

        auth_thread.join()

        return flow.step2_exchange(auth_thread.code)

    def get_app_token(self, tenant_id, resource):
        url = AZURE_TOKEN_URI_TPL.format(tenant_id=tenant_id)

        r = requests.post(url, {
            "client_id": self.app_client_id,
            "client_secret": self.app_client_secret,
            "grant_type": "client_credentials",
            "resource": resource
        })

        logger.debug("App Token Request response: %s", r.text)
        return AccessTokenCredentials(r.json()["access_token"], USER_AGENT)
