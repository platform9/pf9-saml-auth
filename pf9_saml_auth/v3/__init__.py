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

import oktaauth
from pf9_saml_auth.v3 import base
from keystoneauth1.extras._saml2 import V3ADFSPassword
from pf9_saml_auth.v3 import adfs
from pf9_saml_auth.v3 import generic
from pf9_saml_auth.v3 import okta
from pf9_saml_auth.v3 import onelogin

_ADFS_AVAILABLE = adfs is not None and V3ADFSPassword is not None
_GENERIC_AVAILABLE = generic is not None
_OKTA_AVAILABLE = okta is not None and oktaauth is not None
_ONELOGIN_AVAILABLE = onelogin is not None

ADFSPassword = adfs.V3ADFSPassword
GenericPassword = generic.Password
OktaPassword = okta.Password
OneloginPassword = onelogin.Password

__all__ = (
    'ADFSPassword',
    'GenericPassword',
    'OktaPassword',
    'OneloginPassword',
)
