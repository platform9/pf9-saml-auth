from setuptools import setup

setup(
    name='pf9-saml-auth',
    version='0.0.2',
    description='Platform9 SAML Authentication Library for OpenStack Identity',
    url='http://github.com/platform9/pf9-saml-auth',
    author='Blake Covarrubias',
    author_email='blake@platform9.com',
    license='BSD',
    packages=[
        'pf9_saml_auth',
        'pf9_saml_auth.v3',
    ],
    install_requires=[
        'keystoneauth1',
        'lxml',
        'oktaauth',
        'python-keystoneclient',
    ],
    zip_safe=False,
    entry_points={
        "keystoneauth1.plugin": [
            "v3pf9samladfs = pf9_saml_auth._loading:V3Pf9ADFSPassword",
            "v3pf9samlokta = pf9_saml_auth._loading:V3Pf9SamlOkta",
            "v3pf9samlonelogin = pf9_saml_auth._loading:V3Pf9SamlOnelogin",
        ]
    }
)
