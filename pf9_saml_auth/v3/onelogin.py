# Copyright 2018 Platform9 Systems, Inc.

# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy
# of the License at

#   http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""OneLogin SAML authentication driver."""
import base64
import re
import urlparse
from pf9_saml_auth.v3 import base


class Password(base.BasePF9SAMLPlugin):
    """onelogin.Password class."""

    def __init__(self, onelogin_client_id, onelogin_client_secret, **kwargs):
        """Class constructor accepting following parameters.

        :param onelogin_client_id: OneLogin API Client ID
        :type onelogin_client_id: string
        :param onelogin_client_secret: OneLogin API Client Secret
        :type onelogin_client_secret: string

        Remaining arguments inherit from parent class.
        """
        self.client_id = onelogin_client_id
        self.client_secret = onelogin_client_secret
        self.session = None

        super(Password, self).__init__(**kwargs)

        self.api_endpoint = 'https://api.us.onelogin.com'

    def _app_info(self):
        """OneLogin-specific application info retrieved from the URL.

        :returns: tuple containing subdomain & APP ID
        :rtype: tuple
        """
        redirect_url = urlparse.urlparse(self._get_redirect_url())
        if re.search("onelogin", redirect_url.hostname):
            subdomain = re.match(
                r"^([a-z0-9\-]+).onelogin.com",
                redirect_url.hostname)
            app_id = re.match(
                r"^\/trust\/saml2\/http-redirect\/sso/(\d+)$",
                redirect_url.path)

            return (subdomain.group(1), app_id.group(1))

    def _authenticate(self, session):
        """Authenticate with identity provider.

        :param session:
        :type session: keystoneauth1.session.Session
        :returns: SAML response
        :rtype: str
        """
        if self.session is None:
            self.session = session

        access_token = self._get_oauth_token()
        subdomain, app_id = self._app_info()
        try:
            saml_response = self._get_saml_assertion(
                access_token,
                app_id,
                subdomain,
            )

            return saml_response
        except Exception as excp:
            raise excp

    def _get_oauth_token(self):
        """Get OAuth token to obtain API access."""
        url = self.api_endpoint + '/auth/oauth2/token'
        headers = {
            'Authorization': [
                'client_id:' + self.client_id,
                'client_secret:' + self.client_secret
            ]
        }

        # Flatten auth headers
        headers['Authorization'] = ','.join(headers['Authorization'])

        headers['Content-Type'] = 'application/json'
        payload = {'grant_type': 'client_credentials'}

        resp = self._post_call(self.session, url, headers, payload)
        for item in resp.json()['data']:
            if 'access_token' in item:
                access_token = item['access_token']
                return access_token

    def _get_saml_assertion(self, access_token, app_id, subdomain):
        """Authenticate with IdP & retrieve SAML assertion.

        :param access_token
        :type access_token: str
        :param app_id
        :type app_id: str
        :param subdomain
        :type subdomain: str
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

        resp = self._post_call(self.session, url, headers, payload)
        saml_assertion = base64.b64decode(resp.json()['data'])

        return saml_assertion

    def mfa_supported(self):
        """
        Check if MFA is supported.

        :rtype: True if MFA supported, False otherwise
        """
        return False
