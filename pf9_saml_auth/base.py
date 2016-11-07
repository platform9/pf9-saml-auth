"""
SamlDriver class
"""

import base64
import sys
import urlparse
import requests


class SamlDriver(object):
    """SamlDriver"""
    def __init__(self, auth_url, username, password, tenant, mfa_passcode=None):
        super(SamlDriver, self).__init__()
        auth_url = urlparse.urlparse(auth_url)
        self.pf9_endpoint = "{0}://{1}".format(
            auth_url.scheme,
            auth_url.hostname
        )
        self.username = username
        self.password = password
        self.tenant = tenant
        self._redirect_url = None
        self._session = requests.Session()

        self.mfa_passcode = mfa_passcode if self.mfa_supported() \
            is True else None

    def get_token(self):
        """
        Authenticate with identity provider
        """
        try:
            saml_response = self._authenticate()

            # Exit if authentication failed
            if saml_response is False:
                sys.exit("Invalid username / password provided.")

            self.get_os_token(saml_response)
            os_token = self.get_unscoped_token()

            tenant_id = self.get_tenant_id(os_token, self.tenant)

            if tenant_id is None:
                sys.exit("Unable to find tenant {0}".format(self.tenant))

            # Return scoped authentication token
            return self.get_scoped_token(os_token, tenant_id)
        except Exception as excp:
            raise excp

    def _authenticate(self):
        """
        Authenticate with identity provider
        """
        raise NotImplementedError

    def mfa_supported(self):
        """
        Check if MFA is supported
        """
        raise NotImplementedError

    def redirect_url(self):
        """
        Return redirect url
        """
        return self._redirect_url or self._get_redirect_url()

    def _get_redirect_url(self):
        try:
            response = requests.get(
                self.pf9_endpoint + "/Shibboleth.sso/Login",
                allow_redirects=False)
        except requests.exceptions.RequestException as excp:
            sys.exit(excp)

        if response.status_code == 302:
            self._redirect_url = response.headers["Location"]

            return self._redirect_url
        else:
            return None

    def _post_call(self, url, headers, payload):
        """
        Helper method to POST data with the correct content type.

        :param url: Target URL
        :param headers: HTTP request headers
        :param payload: Request payload
        :type url: str
        :type headers: dict
        :type payload: str
        """
        post_args = dict(headers=headers, allow_redirects=False)
        if headers['Content-Type'] == 'application/x-www-form-urlencoded':
            post_args['data'] = payload
        elif headers['Content-Type'] == 'application/json':
            post_args['json'] = payload

        return self._session.post(url, **post_args)

    def get_os_token(self, saml_assert):
        """
        Provide authenticated SAML assertion to Shibboleth to obtain
        authentication cookie.

        :param saml_assert: SAML assertion
        :type saml_assert: str
        """
        url = self.pf9_endpoint + '/Shibboleth.sso/SAML2/POST'
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        payload = {'SAMLResponse': base64.b64encode(saml_assert)}

        self._post_call(url, headers, payload)

    def get_unscoped_token(self):
        """
        Obtain unscoped token from Keystone using Shibboleth authentication
        cookie.
        """
        saml_auth_url = '/keystone_admin/v3/OS-FEDERATION/identity_providers/'
        saml_auth_url += 'IDP1/protocols/saml2/auth'

        try:
            resp = self._session.get(self.pf9_endpoint + saml_auth_url)

            if resp.status_code == 401:
                sys.exit("Unable to obtain unscoped token. Incorrect username / password.")
            elif resp.status_code == 201:
                os_token = resp.headers['X-Subject-Token']
                return os_token
            else:
                sys.exit("HTTP %d. Unable to obtain unscoped token."
                         % resp.status_code)
        except requests.exceptions.RequestException as excp:
            sys.exit(excp)

        os_token = resp.headers['X-Subject-Token']
        return os_token

    def get_tenant_id(self, token, tenant):
        """
        Obtain tenant / project ID for the given tenant.

        :param token: Unscoped Keystone token
        :param tenant: Tenant / Project name
        :type token: str
        :type tenant: str
        """
        url = self.pf9_endpoint + '/keystone/v3/OS-FEDERATION/projects'
        headers = {'X-Auth-Token': token}
        try:
            resp = self._session.get(
                url,
                headers=headers,
                allow_redirects=False)
        except requests.exceptions.RequestException:
            return None

        tenant_id = None
        if resp.status_code == 200:
            for project in resp.json()['projects']:
                if tenant == project['name']:
                    tenant_id = project['id']
                    break

        return tenant_id

    def get_scoped_token(self, os_token, tenant_id):
        """
        Obtain scoped token for the given tenant.

        :param os_token: Unscoped token
        :param tenant_id: UUID of tenant / project
        :type os_token: str
        :type tenant_id: str
        """
        url = self.pf9_endpoint + '/keystone/v3/auth/tokens?nocatalog'
        headers = {'Content-Type': 'application/json'}
        payload = {
            "auth": {
                "identity": {
                    "methods": ["saml2"],
                    "saml2": {
                        "id": os_token
                    }
                },
                "scope": {
                    "project": {"id": tenant_id}
                }
            }
        }

        resp = self._post_call(url, headers, payload)
        if resp.status_code == 201:
            return resp.headers['X-Subject-Token']
        else:
            return None
