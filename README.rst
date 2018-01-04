pf9-saml-auth
=============

pf9-saml-auth is a set of OpenStack Keystone authentication plugins for enabling
federated authentication against non-ECP compliant SAML identity providers.

Supported providers
-------------------

- Microsoft AD FS
- Okta_
- Onelogin_

Installation
------------

.. code:: bash

    pip install pf9-saml-auth


Example CLI Usage
=================

OpenStack RC
------------

.. code:: bash

    export OS_AUTH_URL="https://<hostname>/keystone/v3"
    export OS_REGION_NAME="<region>"
    export OS_USERNAME="<IdP username>"
    export OS_PASSWORD="<IdP password>"
    export OS_TENANT_NAME="<tenant>"
    export OS_PROJECT_DOMAIN_ID=${OS_PROJECT_DOMAIN_ID:-"default"}
    export OS_IDENTITY_API_VERSION=3
    export OS_IDENTITY_PROVIDER=${OS_IDENTITY_PROVIDER:-"IDP1"}
    export OS_PROTOCOL=saml2
    export OS_AUTH_TYPE=v3pf9samlokta

Then execute the **openstack** CLI utility in interactive mode.

.. code:: bash

    $ openstack
    (openstack)
    server list


Example Python program
----------------------

.. code:: python

    import pf9_saml_auth
    from keystoneauth1 import session
    from novaclient import client as nova_client


    def main():
        auth = pf9_saml_auth.V3Pf9SamlOkta(
            auth_url='https://<hostname>/keystone/v3',
            username='<IdP username>',
            password='<IdP password>',
            protocol='saml2',
            identity_provider='IDP1',
            project_name='<tenant>',
            project_domain_name='default',
        )

        # Create Keystone authentication session
        sess = session.Session(auth=auth)

        # Create OpenStack service clients
        nova = nova_client.Client(2, session=sess)


    if __name__ == '__main__':
        main()


.. _Okta: http://www.okta.com/
.. _Onelogin: http://www.onelogin.com/