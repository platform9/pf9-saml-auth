"""
Okta SAML authentication driver
"""
import re
import urlparse

from oktaauth import models
from pf9_saml_auth.base import SamlDriver


class OktaAuthDriver(SamlDriver):
    """OktaAuthDriver"""
    def __init__(self, auth_url, username, password, tenant):
        super(OktaAuthDriver, self).__init__(
            auth_url,
            username,
            password,
            tenant)

    def _authenticate(self):
        """
        Authenticate with identity provider
        """
        app_type, app_id = self._app_info()
        okta = models.OktaSamlAuth(
            urlparse.urlparse(self.redirect_url()).hostname,
            app_type,
            app_id,
            self.username,
            self.password,
            self.mfa_passcode,
        )

        try:
            saml_response = okta.auth()

            return saml_response
        except Exception as excp:
            raise excp

    def _app_info(self):
        """
        Okta-specific application info retrieved from the URL
        """

        redirect_url = urlparse.urlparse(self.redirect_url())
        if re.search("okta", redirect_url.hostname):
            app_info = re.match(
                r"^\/app\/(\w+)\/(\w+)\/sso/saml$",
                redirect_url.path
            )
            return app_info.groups(0)

    def mfa_supported(self):
        """
        Check if MFA is supported
        """
        return True
