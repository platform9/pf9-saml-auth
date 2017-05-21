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

from pf9_saml_auth import v3

_ADFS_AVAILABLE = v3._ADFS_AVAILABLE
_GENERIC_AVAILABLE = v3._GENERIC_AVAILABLE
_OKTA_AVAILABLE = v3._OKTA_AVAILABLE
_ONELOGIN_AVAILABLE = v3._ONELOGIN_AVAILABLE

V3Pf9ADFSPassword = v3.ADFSPassword
V3Pf9SamlGeneric = v3.GenericPassword
V3Pf9SamlOkta = v3.OktaPassword
V3Pf9SamlOnelogin = v3.OneloginPassword

__all__ = (
    'V3Pf9ADFSPassword',
    'V3Pf9SamlGeneric',
    'V3Pf9SamlOkta',
    'V3Pf9SamlOnelogin',
)
