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
import os

from setuptools import setup


def read(fname):
    with open(os.path.join(os.path.dirname(__file__), fname)) as fn:
        return fn.read()

with open('requirements.txt') as f:
    required = f.read().splitlines()

setup(
    name='pf9-saml-auth',
    version='0.0.2',
    description='Platform9 SAML Authentication Library for OpenStack Identity',
    long_description=read('README.rst'),
    url='http://github.com/platform9/pf9-saml-auth',
    author='Blake Covarrubias',
    author_email='blake@platform9.com',
    license='Apache License 2.0',
    packages=[
        'pf9_saml_auth',
        'pf9_saml_auth.v3',
    ],
    install_requires=required,
    zip_safe=False,
    entry_points={
        "keystoneauth1.plugin": [
            "v3pf9samladfs = pf9_saml_auth._loading:V3Pf9ADFSPassword",
            "v3pf9samlokta = pf9_saml_auth._loading:V3Pf9SamlOkta",
            "v3pf9samlonelogin = pf9_saml_auth._loading:V3Pf9SamlOnelogin",
        ]
    }
)
