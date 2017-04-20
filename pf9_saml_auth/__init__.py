from pf9_saml_auth import v3

_ADFS_AVAILABLE = v3._ADFS_AVAILABLE
_OKTA_AVAILABLE = v3._OKTA_AVAILABLE
_ONELOGIN_AVAILABLE = v3._ONELOGIN_AVAILABLE

V3Pf9ADFSPassword = v3.ADFSPassword
V3Pf9SamlOkta = v3.OktaPassword
V3Pf9SamlOnelogin = v3.OneloginPassword

__all__ = ('V3Pf9ADFSPassword', 'V3Pf9SamlOkta', 'V3Pf9SamlOnelogin')
