# -*- coding: utf-8 -*-
#
# Utilities for dealing with blacklists
#
from __future__ import absolute_import
from __future__ import unicode_literals

import logging
import os
import re

import six

from osxcollector.output_filters.exceptions import BadDomainError
from osxcollector.output_filters.exceptions import MissingConfigError
from osxcollector.output_filters.util.dict_utils import DictUtils
from osxcollector.output_filters.util.domains import clean_domain


def create_blacklist(config_chunk, data_feeds={}):
    """Reads the config and builds a Blacklist.

    The blacklist config is sufficiently complex that much of this method deals with simply validating config

    Args:
        config_chunk: A dict of config for building the blacklist
        data_feeds: Dict of generator functions returning the blacklist data
    Returns:
        A Blacklist
    Raises:
        MissingConfigError - when required key does not exist.
    """
    required_keys = ['blacklist_name', 'blacklist_keys']
    if not all([key in config_chunk for key in required_keys]):
        raise MissingConfigError('Blacklist config is missing a required key.\nRequired keys are: {0}'.format(repr(required_keys)))

    if not isinstance(config_chunk['blacklist_keys'], list):
        raise MissingConfigError('The value of \'blacklist_keys\' in Blacklist config must be a list')

    blacklist_name = config_chunk.get('blacklist_name')
    blacklist_keys = config_chunk.get('blacklist_keys')
    blacklist_file_path = config_chunk.get('blacklist_file_path')
    blacklist_data_feed = config_chunk.get('blacklist_data_feed')
    if blacklist_file_path:
        if not os.path.exists(blacklist_file_path):
            raise MissingConfigError('The blacklist file {} does not exist'.format(blacklist_file_path))
        blacklist_data_generator = _read_blacklist_file(blacklist_file_path)
    elif blacklist_data_feed:
        if blacklist_data_feed not in data_feeds:
            raise MissingConfigError('Data feed {} not found among provided generators'.format(blacklist_data_feed))
        blacklist_data_generator = data_feeds[blacklist_data_feed]()
    else:
        raise MissingConfigError('Blacklist config is missing a data input.\nEither select a file or a generator object')
    blacklist_is_regex = config_chunk.get('blacklist_is_regex', False)
    blacklist_is_domains = config_chunk.get('blacklist_is_domains', False)
    return Blacklist(blacklist_name, blacklist_keys, blacklist_data_generator, blacklist_is_regex, blacklist_is_domains)


def _read_blacklist_file(filepath):
    """ Parse blacklist file """
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                yield line


class Blacklist(object):

    def __init__(self, name, blacklisted_keys, input_generator, is_regex=False, is_domains=False):
        """Build a blacklist from the data in the blacklist file.

        Built in smarts make it easy to build a blacklist of domains

        Raises:
            MissingConfigError - when required config key does not exist.
        """
        self._name = name
        self._blacklisted_keys = blacklisted_keys
        self._is_domains = is_domains
        self._is_regex = is_regex or self._is_domains
        self._blacklisted_values = dict(
            self._convert_to_matching_term(val) for val in input_generator if val
        )
        self._blacklisted_values.pop(None, None)

    def _convert_to_matching_term(self, blacklisted_value):
        """Convert a blacklisted_value to a regex.

        Args:
            blacklisted_value - string of value on a blacklist
            blacklist_is_domains - Boolean if true, the blacklisted_value is treated as a domain.
        Returns:
            MatchingTerm
        """
        display_name = blacklisted_value

        if self._is_domains:
            try:
                domain = clean_domain(blacklisted_value)
            except BadDomainError:
                if not isinstance(blacklisted_value, six.text_type):
                    blacklisted_value = blacklisted_value.decode('utf8')
                logging.warning(
                    u'Blacklisted value "{0}" cannot be resolved as a domain name'
                    .format(blacklisted_value),
                )
                return None, None

            blacklisted_value = re.compile(r'^(.+\.)*{0}$'.format(re.escape(domain)))

        elif self._is_regex:
            blacklisted_value = re.compile(blacklisted_value)

        return blacklisted_value, display_name

    def match_line(self, blob):
        """Determines whether a line matches the blacklist.

        Returns:
            String of matched term is the value matches, None otherwise
        """
        for key in self._blacklisted_keys:
            values = DictUtils.get_deep(blob, key)
            if not values:
                continue

            matching_term = self.match_values(values)
            if matching_term:
                return matching_term

        return None

    def match_values(self, values):
        """Determines whether an array of values match the blacklist.

        Returns:
            String of matched term is the value matches, None otherwise
        """
        if not isinstance(values, list):
            values = [values]

        for val in values:
            if self._is_regex or self._is_domains:
                return next(
                    (
                        name for term, name in six.iteritems(self._blacklisted_values) if term.search(val)
                    ), None,
                )
            else:
                return self._blacklisted_values.get(val, None)
        return None

    @property
    def name(self):
        return self._name
