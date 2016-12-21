"""Okta SAML authentication driver."""
import re
import urlparse
from oktaauth import models
from pf9_saml_auth.v3 import base


class Password(base.BasePF9SAMLPlugin):
    """okta.Password class."""

    def __init__(self, **kwargs):
        """Class constructor accepting following parameters.

        Inherits input parameters from parent class.
        """
        self.session = None

        super(Password, self).__init__(**kwargs)

        if not self._mfa_supported():
            self._mfa_passcode = None

    def _app_info(self):
        """Okta-specific application info retrieved from the URL.

        :returns: Tuple containing app type & ID
        :rtype: tuple
        """
        redirect_url = urlparse.urlparse(self._redirect_url())
        if re.search("okta", redirect_url.hostname):
            app_info = re.match(
                r"^\/app\/(\w+)\/(\w+)\/sso/saml$",
                redirect_url.path
            )
            return app_info.groups(0)

    def _authenticate(self, session):
        """Authenticate with identity provider.

        :param session
        :type session: keystoneauth1.session.Session
        :returns: SAML response
        :rtype: str
        """
        if self.session is None:
            self.session = session

        app_type, app_id = self._app_info()
        okta = models.OktaSamlAuth(
            urlparse.urlparse(self._redirect_url()).hostname,
            app_type,
            app_id,
            self.username,
            self.password,
            self._mfa_passcode,
        )

        try:
            saml_response = okta.auth()

            return saml_response
        except Exception as excp:
            raise excp

    def _mfa_supported(self):
        """Check if MFA is supported.

        :returns: Boolean indicating if MFA is supported.
        :rtype: True if MFA supported, False otherwise
        """
        return False
