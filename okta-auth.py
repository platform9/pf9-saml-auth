#!/usr/bin/env python

import base64
import os
import re
import sys
import urlparse
import requests

from oktaauth import models

def post_call(session, url, headers, payload):
    """
    Helper method to POST data with the correct content type.

    :param session: requests.Session
    :param url: Target URL
    :param headers: HTTP request headers
    :param payload: Request payload
    :type session: list
    :type url: str
    :type headers: dict
    :type payload: str
    """
    post_args = dict(headers=headers, allow_redirects=False)
    if headers['Content-Type'] == 'application/x-www-form-urlencoded':
        post_args['data'] = payload
    elif headers['Content-Type'] == 'application/json':
        post_args['json'] = payload

    return session.post(url, **post_args)

def get_os_token(session, saml_assert, pf9_endpoint):
    """
    Provide authenticated SAML assertion to Shibboleth to obtain authentication
    cookie.

    :param session: requests.Session
    :param saml_assert: SAML assertion
    :param pf9_endpoint: Platform9 controller
    :type session: list
    :type saml_assert: str
    :type pf9_endpoint: str
    """
    url = pf9_endpoint + '/Shibboleth.sso/SAML2/POST'
    headers = {'Content-Type':'application/x-www-form-urlencoded'}
    payload = {'SAMLResponse': base64.b64encode(saml_assert)}

    post_call(session, url, headers, payload)

def get_unscoped_token(session, pf9_endpoint):
    """
    Obtain unscoped token from Keystone using Shibboleth authentication cookie.

    :param session: requests.Session
    :param pf9_endpoint: Platform9 controller
    :type session: list
    :type pf9_endpoint: str
    """
    resp = session.get(pf9_endpoint + '/keystone_admin/v3/OS-FEDERATION/identity_providers/IDP1/protocols/saml2/auth')
    os_token = resp.headers['X-Subject-Token']
    return os_token

def get_tenant_id(session, token, tenant, pf9_endpoint):
    """
    Obtain tenant / project ID for the given tenant.

    :param session: requests.Session
    :param token: Unscoped Keystone token
    :param tenant: Tenant / Project name
    :param pf9_endpoint: FQDN of Platform9 controller
    :type session: list
    :type token: str
    :type tenant: str
    :type pf9_endpoint: str
    """
    url = pf9_endpoint + '/keystone/v3/OS-FEDERATION/projects'
    headers = {'X-Auth-Token': token}
    resp = session.get(url, headers=headers, allow_redirects=False)

    tenant_id = None
    for project in resp.json()['projects']:
        if tenant == project['name']:
            tenant_id = project['id']
            break

    return tenant_id

def get_scoped_token(session, os_token, tenant_id, pf9_endpoint):
    """
    Obtain scoped token for the given tenant.

    :param session: requests.Session
    :param os_token: Unscoped token
    :param tenant_id: UUID of tenant / project
    :param pf9_endpoint: Platform9 controller
    :type session: list
    :type os_token: str
    :type tenant_id: str
    :type pf9_endpoint: str
    """
    url = pf9_endpoint + '/keystone/v3/auth/tokens?nocatalog'
    headers = {'Content-Type':'application/json'}
    payload = {
        "auth": {
            "identity": {
                "methods": ["saml2"],
                "saml2": {
                    "id": os_token
                }
            },
            "scope": {
                "project": {"id": tenant_id}
            }
        }
    }

    resp = post_call(session, url, headers, payload)
    return resp.headers['X-Subject-Token']

def main():
    auth_url = urlparse.urlparse(os.environ["OS_AUTH_URL"])
    pf9_endpoint = "{0}://{1}".format(auth_url.scheme, auth_url.hostname)
    username = os.environ["OS_USERNAME"]
    password = os.environ["OS_PASSWORD"]
    tenant = os.environ["OS_TENANT_NAME"]

    response = requests.get(pf9_endpoint + "/Shibboleth.sso/Login", allow_redirects=False)
    if response.status_code == 302:
        redirect_url = urlparse.urlparse(response.headers["Location"])

        if re.search("okta", redirect_url.hostname):
            app_info = re.match(r"^\/app\/(\w+)\/(\w+)\/sso/saml$", redirect_url.path)

            okta = models.OktaSamlAuth(
                redirect_url.hostname,
                app_info.group(1),
                app_info.group(2),
                username,
                password,
                ""
            )

            try:
                saml_response = okta.auth()
            except Exception as exp:
                print exp

            # Exit if authentication failed
            if saml_response is False:
                sys.exit("Invalid username / password provided.")

            session = requests.Session()
            get_os_token(session, saml_response, pf9_endpoint)
            os_token = get_unscoped_token(session, pf9_endpoint)

            tenant_id = get_tenant_id(session, os_token, tenant, pf9_endpoint)
            if tenant_id is None:
                sys.exit("Unable to find tenant {0}".format(tenant))

            # Return scoped authentication token
            print get_scoped_token(session, os_token, tenant_id, pf9_endpoint)
        else:
            sys.exit("Unknown SAML provider.")

if __name__ == '__main__':
    main()
