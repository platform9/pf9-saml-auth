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

"""Platform9 ADFS authentication driver."""
from keystoneauth1.extras._saml2 import V3ADFSPassword
from keystoneauth1 import access


def __pf9_adfs_init(self, service_provider_endpoint,
                    service_provider_entity_id=None, **kwargs):
    """Constructor for ``ADFSPassword``.

    :param service_provider_endpoint: Endpoint where an assertion is being
            sent, for instance: ``https://host.domain/Shibboleth.sso/ADFS``
    :type service_provider_endpoint: string
    :param service_provider_entity_id: SP SAML entity ID
    :type service_provider_entity_id: string

    Remaining arguments inherit from parent class.
    """
    super(V3ADFSPassword, self).__init__(**kwargs)

    self.service_provider_endpoint = service_provider_endpoint
    self.service_provider_entity_id = service_provider_entity_id \
        or service_provider_endpoint


def __pf9_set_wsa_address(self, address):
    """Set WS-Trust Address.

    :param address:
    :type address: str
    """
    APPLIES_TO_NAMESPACES = self.NAMESPACES
    APPLIES_TO_NAMESPACES.update({
        'trust': 'http://docs.oasis-open.org/ws-sx/ws-trust/200512',
        'wsp': 'http://schemas.xmlsoap.org/ws/2004/09/policy',
        'wsa': 'http://www.w3.org/2005/08/addressing'

    })

    wsa_address_xpath = ''.join((
        '/s:Envelope/s:Body/trust:RequestSecurityToken/wsp:AppliesTo/',
        'wsa:EndpointReference/wsa:Address'
    ))

    # Update WSA address
    self.prepared_request.xpath(
        wsa_address_xpath,
        namespaces=APPLIES_TO_NAMESPACES
    )[0].text = address


def __pf9_get_unscoped_auth_ref(self, session, *kwargs):
    """Obtain unscoped token after authenticating with SAML IdP.

    Replace V3ADFSPassword.get_unscoped_auth_ref() to add
    __pf9_set_wsa_address() function.

    :param session:
    :type session: keystoneauth1.session.Session
    """
    self._prepare_adfs_request()
    self.__pf9_set_wsa_address(self.service_provider_entity_id)
    self._get_adfs_security_token(session)
    self._prepare_sp_request()
    self._send_assertion_to_service_provider(session)
    self._access_service_provider(session)

    return access.create(resp=self.authenticated_response)


# Monkey patch V3ADFSPassword with Platform9 changes.
V3ADFSPassword.__init__ = __pf9_adfs_init
V3ADFSPassword.__pf9_set_wsa_address = __pf9_set_wsa_address
V3ADFSPassword.get_unscoped_auth_ref = __pf9_get_unscoped_auth_ref
