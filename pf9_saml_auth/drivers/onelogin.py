"""
OneLogin SAML authentication driver
"""
import base64
import collections
import re
import urlparse

from pf9_saml_auth.base import SamlDriver


class OneLoginAuthDriver(SamlDriver):
    """OneLoginAuthDriver"""
    def __init__(self, **args):
        if 'client_id' in args:
            self.client_id = args['client_id']
            del args['client_id']
        if 'client_secret' in args:
            self.client_secret = args['client_secret']
            del args['client_secret']
        super(OneLoginAuthDriver, self).__init__(**args)

        self.api_endpoint = 'https://api.us.onelogin.com'

    def _flatten_headers(self, headers):
        for key, value in list(headers.items()):
            if isinstance(value, collections.Iterable):
                headers[key] = ','.join(value)

            return headers

    def _authenticate(self):
        """
        Authenticate with identity provider
        """

        access_token = self.get_oauth_token()
        subdomain, app_id = self._app_info()
        try:
            saml_response = self.get_saml_assert(
                access_token,
                app_id,
                subdomain,
            )

            return saml_response
        except Exception as excp:
            raise excp

    def _app_info(self):
        """
        OneLogin-specific application info retrieved from the URL
        """
        redirect_url = urlparse.urlparse(self.redirect_url())
        if re.search("onelogin", redirect_url.hostname):
            subdomain = re.match(
                r"^([a-z0-9\-]+).onelogin.com",
                redirect_url.hostname)
            app_id = re.match(
                r"^\/trust\/saml2\/http-redirect\/sso/(\d+)$",
                redirect_url.path)

            return (subdomain.group(1), app_id.group(1))

    def mfa_supported(self):
        """
        Check if MFA is supported
        """
        return True

    def get_oauth_token(self):
        """
        Get OAuth token to obtain API access.
        """
        url = self.api_endpoint + '/auth/oauth2/token'
        headers = {
            'Authorization': [
                'client_id:' + self.client_id,
                'client_secret:' + self.client_secret
            ]
        }
        self._flatten_headers(headers)
        headers['Content-Type'] = 'application/json'
        payload = {'grant_type': 'client_credentials'}

        resp = self._post_call(url, headers, payload)
        for item in resp.json()['data']:
            if 'access_token' in item:
                access_token = item['access_token']
                return access_token

    def get_saml_assert(self, access_token, app_id, subdomain):
        """
        Authenticate with IdP & retrieve SAML assertion
        """
        url = self.api_endpoint + '/api/1/saml_assertion'
        headers = {
            'Authorization': 'bearer:' + access_token,
            'Content-Type': 'application/json'
        }

        payload = {
            'username_or_email': self.username,
            'password': self.password,
            'app_id': app_id,
            'subdomain': subdomain
        }

        resp = self._post_call(url, headers, payload)
        saml_assert = base64.b64decode(resp.json()['data'])

        return saml_assert
