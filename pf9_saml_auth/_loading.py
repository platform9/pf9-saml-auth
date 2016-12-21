# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import pf9_saml_auth
from keystoneauth1 import loading


class V3Pf9SamlOkta(loading.BaseFederationLoader):

    @property
    def plugin_class(self):
        return pf9_saml_auth.V3Pf9SamlOkta

    @property
    def available(self):
        return pf9_saml_auth._OKTA_AVAILABLE

    def get_options(self):
        options = super(V3Pf9SamlOkta, self).get_options()

        options.extend([
            loading.Opt('username', help='Username'),
            loading.Opt('password', secret=True, help='Password')
        ])

        return options


class V3Pf9SamlOnelogin(loading.BaseFederationLoader):

    @property
    def plugin_class(self):
        return pf9_saml_auth.V3Pf9SamlOnelogin

    @property
    def available(self):
        return pf9_saml_auth._ONELOGIN_AVAILABLE

    def get_options(self):
        options = super(V3Pf9SamlOnelogin, self).get_options()

        options.extend([
            loading.Opt('username', help='Username'),
            loading.Opt('password', secret=True, help='Password'),
            loading.Opt(
                'onelogin-client-id',
                help='OneLogin API Client ID'
            ),
            loading.Opt(
                'onelogin-client-secret',
                secret=True,
                help='OneLogin API Client Secret'
            ),
        ])

        return options
