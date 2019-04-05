# -*- coding: utf-8 -*-
#
# Config is a very simplistic class for reading YAML config.
#
from __future__ import absolute_import
from __future__ import unicode_literals

import os

import yaml
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

from osxcollector.output_filters.exceptions import MissingConfigError
from osxcollector.output_filters.util.dict_utils import DictUtils


def config_get_deep(key, default=None):
    """Reads from the config.

    Args:
        key: Dictionary key to lookup in config
        default: Value to return if key is not found
    Returns:
        Value from config or default if not found otherwise
    """
    return DictUtils.get_deep(_read_config(), key, default)


def _read_config():
    """Reads and parses the YAML file.

    Returns:
        dict of config
    """
    with open(_config_file_path()) as source:
        return yaml.load(source.read(), Loader=Loader)


def _config_file_path():
    """Find the path to the config file.

    Returns:
        String file path
    Raises:
        MissingConfigError if no config file is found
    """
    for loc in os.curdir, os.path.expanduser('~'), os.environ.get('OSXCOLLECTOR_CONF', ''):
        path = os.path.join(loc, 'osxcollector.yaml')
        if os.path.exists(path):
            return path
    raise MissingConfigError()
