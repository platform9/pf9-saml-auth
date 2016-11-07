"""
Driver initialization
"""
import sys
import inspect
import importlib

from pf9_saml_auth.base import SamlDriver

__all__ = [
    'SamlDriver',
    'get_driver'
]

# Verify Python Version that is running
try:
    if not(sys.version_info.major == 2 and sys.version_info.minor == 7) and \
            not sys.version_info.major == 3:
        raise RuntimeError('pf9_saml_auth requires Python 2.7 or Python3')
except AttributeError:
    raise RuntimeError('pf9_saml_auth requires Python 2.7 or Python3')


def get_driver(module_name):
    """
    Searches for driver in drivers/ directory & returns module if found.
    Raises exception if not found.
    """

    if not len(module_name) > 0:
        raise Exception('Please provide a valid driver name.')

    try:
        # Only lowercase allowed
        module_name = module_name.lower()
        module = importlib.import_module(
            "." + module_name,
            package='pf9_saml_auth.drivers')
    except ImportError:
        raise Exception(
            'Cannot import driver for "{install_name}". \
            Is the driver installed?'.format(
                install_name=module_name
            )
        )

    for name, obj in inspect.getmembers(module):
        if inspect.isclass(obj) and issubclass(obj, SamlDriver):
            return obj
