# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

import pytest
from mock import patch

from osxcollector.output_filters.util.config import config_get_deep


class TestCreateBlacklist:

    @pytest.fixture(scope='module', autouse=True)
    def patched_config(self):
        config_initial_contents = {
            'a': 'b',
            'c': {'d': 'e'},
            'f': 1,
            'g': ['apple', 'banana'],
        }
        with patch('osxcollector.output_filters.util.config._read_config', return_value=config_initial_contents):
            yield

    def test_read_top_level_key(self):
        assert config_get_deep('a') == 'b'

    def test_read_multi_level_key(self):
        assert config_get_deep('c.d') == 'e'

    def test_numeric_val(self):
        assert config_get_deep('f') == 1

    def test_list_val(self):
        assert config_get_deep('g') == ['apple', 'banana']
