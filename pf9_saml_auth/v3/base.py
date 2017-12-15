"""BasePF9SAMLPlugin class."""

import base64
import sys
import urlparse

from keystoneauth1 import access
from keystoneauth1 import exceptions
from keystoneauth1.identity import v3


class _Pf9Saml2TokenAuthMethod(v3.AuthMethod):
    _method_parameters = []  # type: List[str]

    def get_auth_data(self, session, auth, headers, **kwargs):
        raise exceptions.MethodNotImplemented('This method should never '
                                              'be called')


class BasePF9SAMLPlugin(v3.FederationBaseAuth):
    """Base PF9 SAML authentication class.

    IDP specific classes should be based off of this.
    """

    _auth_method_class = _Pf9Saml2TokenAuthMethod

    def __init__(
        self,
        auth_url,
        username,
        password,
        protocol,
        identity_provider,
        **kwargs
    ):
        """
        Class constructor accepting following parameters.

        :param auth_url: URL of the Identity Service
        :type auth_url: string
        :param username: User's login
        :type username: string
        :param password: User's password
        :type password: string
        :param protocol: Protocol to be used for the authentication.
                         The name must be equal to one configured at the
                         keystone sp side. This value is used for building
                         dynamic authentication URL.
                         Typical value would be: saml2
        :type protocol: string
        :param identity_provider: Name of the Identity Provider the client
                                  will authenticate against. This parameter
                                  will be used to build a dynamic URL used to
                                  obtain unscoped OpenStack token.
        :type identity_provider: string
        """
        super(BasePF9SAMLPlugin, self).__init__(
            auth_url=auth_url,
            identity_provider=identity_provider,
            protocol=protocol,
            **kwargs)
        self.username = username
        self.password = password
        self.__redirect_url = None

        _auth_url = urlparse.urlparse(auth_url)
        self._pf9_endpoint = "{0}://{1}".format(
            _auth_url.scheme,
            _auth_url.netloc,
        )

    def _authenticate(self, session):
        """Authenticate with identity provider.

        :param session
        :type session: keystoneauth1.session.Session
        """
        raise NotImplementedError

    def _cookies(self, session):
        """
        Check if cookie jar is not empty.

        keystoneauth1.session.Session object doesn't have a cookies attribute.
        We should then try fetching cookies from the underlying
        requests.Session object. If that fails too, there is something wrong
        and let Python raise the AttributeError.
        :param session
        :type session: keystoneauth1.session.Session
        :returns: Boolean indicating MFA support
        :rtype: True if cookie jar is nonempty, False otherwise
        :raises AttributeError: in case cookies are not find anywhere
        """
        try:
            return bool(session.cookies)
        except AttributeError:
            pass

        return bool(session.session.cookies)

    def _get_auth_cookie(self, session, saml_assert):
        """Provide authenticated SAML assertion & obtain unscoped token.

        :param session
        :type session: keystoneauth1.session.Session
        :param saml_assert: SAML assertion
        :type saml_assert: str
        """
        url = self._pf9_endpoint + '/Shibboleth.sso/SAML2/POST'
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        payload = {'SAMLResponse': base64.b64encode(saml_assert)}

        self._post_call(session, url, headers, payload)

    def _get_redirect_url(self):
        try:
            response = self.session.get(
                self._pf9_endpoint + "/Shibboleth.sso/Login",
                authenticated=False,
                redirect=False)
        except Exception as excp:
            sys.exit(excp)

        if response.status_code == 302:
            self.__redirect_url = response.headers["Location"]

            return self.__redirect_url
        else:
            return None

    def _mfa_supported(self):
        """Check if MFA is supported."""
        raise NotImplementedError

    def _post_call(self, session, url, headers, payload, authenticated=False):
        """Helper method to POST data with the correct content type.

        :param session
        :type session: keystoneauth1.session.Session
        :param url: Target URL
        :param headers: HTTP request headers
        :param payload: Request payload
        :type url: str
        :type headers: dict
        :type payload: str
        """
        post_args = dict(headers=headers)
        if headers['Content-Type'] == 'application/x-www-form-urlencoded':
            post_args['data'] = payload
        elif headers['Content-Type'] == 'application/json':
            post_args['json'] = payload
        return session.post(
            url,
            authenticated=authenticated,
            redirect=False,
            **post_args
        )

    def _redirect_url(self):
        """Return redirect url."""
        return self.__redirect_url or self._get_redirect_url()

    @property
    def federated_token_url(self):
        """Full URL where authorization data is sent.

        Override v3.FederationBaseAuth.federated_token_url to provide the
        auth URL for Platform9 managed OpenStack.

        :returns: URL containing federated token auth endpoint
        :rtype: str
        """
        auth_url = self.auth_url.replace('keystone', 'keystone_admin')
        values = {
            'host': auth_url.rstrip('/'),
            'identity_provider': self.identity_provider,
            'protocol': self.protocol
        }
        url = ("%(host)s/OS-FEDERATION/identity_providers/"
               "%(identity_provider)s/protocols/%(protocol)s/auth")
        url = url % values

        return url

    def get_unscoped_auth_ref(self, session, **kwargs):
        """Obtain unscoped token after authenticating with SAML IdP.

        :param session:
        :type session: keystoneauth1.session.Session
        """
        saml_response = self._authenticate(session)

        # Exit if authentication failed
        if saml_response is False:
            sys.exit("Invalid username / password provided.")

        self._get_auth_cookie(session, saml_response)

        if self._cookies(session) is False:
            raise exceptions.AuthorizationFailure(
                "Session object doesn't contain a cookie, therefore you are "
                "not allowed to enter the Identity Provider's protected area.")

        resp = session.get(self.federated_token_url,
                           authenticated=False,
                           cookies=session.session.cookies.get_dict())

        return access.create(body=resp.json(), resp=resp)
