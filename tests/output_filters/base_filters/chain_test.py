# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

from osxcollector.output_filters.base_filters.chain import ChainFilter
from osxcollector.output_filters.base_filters.output_filter import OutputFilter
from tests.output_filters.run_filter_test import RunFilterTest


class TestChainFilter(RunFilterTest):

    def test_run_chain_filter(self):
        input_blobs = [
            {'fungo': 'dingo', 'bingo': [11, 37], 'banana': {'a': 11}},
            {'span': 'div', 'head': ['tail', 22], 'orange': {'lemmon': 'zits'}},
        ]
        self.run_test(lambda: ChainFilter([OutputFilter(), OutputFilter()]), input_blobs=input_blobs, expected_output_blobs=input_blobs)
