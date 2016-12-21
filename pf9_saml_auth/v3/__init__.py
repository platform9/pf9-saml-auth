import oktaauth
from pf9_saml_auth.v3 import base
from pf9_saml_auth.v3 import okta
from pf9_saml_auth.v3 import onelogin

_OKTA_AVAILABLE = okta is not None and oktaauth is not None
_ONELOGIN_AVAILABLE = onelogin is not None

OktaPassword = okta.Password
OneloginPassword = onelogin.Password

__all__ = ('OktaPassword', 'OneloginPassword')
