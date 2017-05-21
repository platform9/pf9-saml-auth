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

"""Generic SAML authentication driver."""
import base64
import re
from urlparse import urlparse

from bs4 import BeautifulSoup
from pf9_saml_auth.v3 import base


class Password(base.BasePF9SAMLPlugin):
    """generic.Password class."""

    def __init__(self, **kwargs):
        """Class constructor accepting following parameters.

        Inherits input parameters from parent class.
        """
        self.formsoup = None
        self.idp_page = None
        self._login_request_params = None
        self.session = None

        super(Password, self).__init__(**kwargs)

        if not self._mfa_supported():
            self._mfa_passcode = None

    def _authenticate(self, session):
        """Authenticate with identity provider.

        :param session
        :type session: keystoneauth1.session.Session
        :returns: SAML response
        :rtype: str
        """
        if self.session is None:
            self.session = session

        idp_url = self._get_redirect_url()

        self.idp_page = self.session.get(
            idp_url,
            authenticated=False,
            verify=True
        )
        self.formsoup = BeautifulSoup(
            self.idp_page.text.decode('utf8'), "html.parser"
        )

        self._login_request_params = self._create_login_request()
        assertion = self._login_to_idp()

        return assertion

    def _create_login_request(self):
        """
        Parse the response and extract all the necessary values in order to
        build a dictionary of all of the form values the IdP expects.
        """
        payload = {}

        for inputtag in self.formsoup.find_all(re.compile('(INPUT|input)')):
            name = inputtag.get('name', '')
            value = inputtag.get('value', '')

            if "user" in name.lower():
                # Make an educated guess that this is the right field for the
                # username
                payload[name] = self.username
            elif "email" in name.lower():
                # Some IdPs also label the username field as 'email'
                payload[name] = self.username
            elif "pass" in name.lower():
                # Make an educated guess that this is the right field for the
                # password
                payload[name] = self.password
            else:
                # Simply populate the parameter with the existing value (picks
                # up hidden fields in the login form)
                if value:
                    payload[name] = value

        return payload

    @staticmethod
    def _get_saml_assertion(response):
        soup = BeautifulSoup(response, "html.parser")

        # Look for the SAMLResponse attribute of the input tag (determined by
        # analyzing the debug print lines above)
        assertion = ''
        for inputtag in soup.find_all('input'):
            if inputtag.get('name') == 'SAMLResponse':
                assertion = inputtag.get('value')

        return base64.b64decode(assertion)

    def _login_to_idp(self):
        for inputtag in self.formsoup.find_all(re.compile('(FORM|form)')):
            action = inputtag.get('action')
            loginid = inputtag.get('id')

            # Skip non-login forms for ADFS
            if loginid and loginid != 'loginForm':
                continue

            if action:
                parsedurl = urlparse(self.idp_page.url)
                idpauthformsubmiturl = "{}://{}{}".format(parsedurl.scheme,
                                                          parsedurl.netloc,
                                                          action)

        # Performs the submission of the IdP login form with the above POST
        # data
        response = self.session.post(
            idpauthformsubmiturl,
            authenticated=False,
            data=self._login_request_params,
        )

        return self._get_saml_assertion(response.text)

    def _mfa_supported(self):
        """Check if MFA is supported.

        :returns: Boolean indicating if MFA is supported.
        :rtype: True if MFA supported, False otherwise
        """
        return False
