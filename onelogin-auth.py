#!/usr/bin/python
import collections
import json
import os
import requests
import urllib

def flatten_headers(headers):
    for key, value in list(headers.items()):
        if isinstance(value, collections.Iterable):
           headers[key] = ','.join(value)

def post_call(session, url, headers, payload):
    if headers['Content-Type'] == 'application/x-www-form-urlencoded':
        resp = session.post(url, headers=headers, data=payload, allow_redirects=False)
    elif headers['Content-Type'] == 'application/json':
        resp = session.post(url, headers=headers, json=payload, allow_redirects=False)

    return resp

def get_oauth_token(session, client_id, client_secret, onelogin_endpoint):
    url = onelogin_endpoint + '/auth/oauth2/token'
    headers = {'Authorization': ['client_id:'+client_id, 'client_secret:'+client_secret]}
    flatten_headers(headers)
    headers['Content-Type'] = 'application/json'
    payload = {'grant_type': 'client_credentials'}

    resp = post_call(session, url, headers, payload)
    for item in resp.json()['data']:
        access_token = item['access_token']

    return access_token

def get_saml_assert(session, access_token, username, password, app_id, subdomain, onelogin_endpoint):
    """
    Authenticate with IdP & retrieve SAML assertion
    """
    url = onelogin_endpoint + '/api/1/saml_assertion'
    headers = {
        'Authorization': 'bearer:' + access_token,
        'Content-Type':'application/json'
    }

    payload = {
        'username_or_email': username,
        'password': password,
        'app_id': app_id,
        'subdomain': subdomain
    }

    resp = post_call(session, url, headers, payload)
    saml_assert = resp.json()['data']

    return saml_assert

def get_os_token(session, saml_assert, pf9_endpoint):
    """
    Provide authenticated SAML assertion to Shibboleth to obtain authentication
    cookie.
    """
    url = pf9_endpoint + '/Shibboleth.sso/SAML2/POST'
    headers = {'Content-Type':'application/x-www-form-urlencoded'}
    payload = urllib.urlencode({'SAMLResponse':saml_assert})

    post_call(session, url, headers, payload)

def get_unscoped_token(session, pf9_endpoint):
    resp = session.get(pf9_endpoint + '/keystone_admin/v3/OS-FEDERATION/identity_providers/IDP1/protocols/saml2/auth')
    os_token = resp.headers['X-Subject-Token']
    return os_token

def get_tenant(session, os_token, tenant, pf9_endpoint):
    url = pf9_endpoint + '/keystone/v3/OS-FEDERATION/projects'
    headers = {'X-Auth-Token': os_token}
    resp = session.get(url, headers=headers, allow_redirects=False)

    for project in resp.json()['projects']:
        if tenant == project['name']:
          tenant_id = project['id']
          # print tenant_id

    return tenant_id

def get_scoped_token(session, os_token, tenant_id, pf9_endpoint):
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
    os_token = resp.headers['X-Subject-Token']
    return os_token
    # with open('token.txt', 'w') as outfile:
    #     outfile.write(os_token)

def main():
    session = requests.Session()

    onelogin_endpoint = 'https://api.us.onelogin.com'
    client_id = ''
    client_secret = ''
    app_id = ''
    subdomain = ''
    username = ''
    password = ''
    tenant = ''
    pf9_endpoint = ''

    access_token = get_oauth_token(session, client_id, client_secret, onelogin_endpoint)
    saml_assert = get_saml_assert(
        session,
        access_token,
        username,
        password,
        app_id,
        subdomain,
        onelogin_endpoint
    )

    get_os_token(session, saml_assert, pf9_endpoint)
    os_token = get_unscoped_token(session, pf9_endpoint)
    tenant_id = get_tenant(session, os_token, tenant, pf9_endpoint)
    print get_scoped_token(session, os_token, tenant_id, pf9_endpoint)

if __name__ == '__main__':
    main()
