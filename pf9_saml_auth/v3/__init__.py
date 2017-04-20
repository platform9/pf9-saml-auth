import oktaauth
from pf9_saml_auth.v3 import base
from keystoneauth1.extras._saml2 import V3ADFSPassword
from pf9_saml_auth.v3 import adfs
from pf9_saml_auth.v3 import okta
from pf9_saml_auth.v3 import onelogin

_ADFS_AVAILABLE = adfs is not None and V3ADFSPassword is not None
_OKTA_AVAILABLE = okta is not None and oktaauth is not None
_ONELOGIN_AVAILABLE = onelogin is not None

ADFSPassword = adfs.V3ADFSPassword
OktaPassword = okta.Password
OneloginPassword = onelogin.Password

__all__ = ('ADFSPassword', 'OktaPassword', 'OneloginPassword')
