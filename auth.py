#!/usr/bin/env python

import os
import pf9_saml_auth


def main():
    """
    Searches for a class derived from the base SamlDriver class in the
    drivers directory.

    .. code-block:: python
        >>> get_driver('okta')
        <class 'pf9_saml_auth.drivers.OktaAuthDriver'>
        >>> get_driver('onelogin')
        <class 'pf9_saml_auth.drivers.OneLoginAuthDriver'>
        >>> get_driver('wrong')
        Excepetion: Cannot import "wrong". Is the library installed?
    """
    driver = pf9_saml_auth.get_driver('')
    saml = driver(
        auth_url=os.environ["OS_AUTH_URL"],
        username=os.environ["OS_USERNAME"],
        password=os.environ["OS_PASSWORD"],
        tenant=os.environ["OS_TENANT_NAME"],
    )

    token = saml.get_token()
    if token is not None:
        print token

if __name__ == '__main__':
    main()
