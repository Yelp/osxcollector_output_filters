# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

from osxcollector.output_filters.base_filters.output_filter import OutputFilter
from tests.output_filters.run_filter_test import RunFilterTest


class TestOutputFilter(RunFilterTest):

    def test_filter_line(self):
        input_blobs = [
            {'fungo': 'dingo', 'bingo': [11, 37], 'banana': {'a': 11}},
            {'span': 'div', 'head': ['tail', 22], 'orange': {'lemmon': 'zits'}},
        ]
        output_filter = OutputFilter()
        for blob in input_blobs:
            output = output_filter.filter_line(blob)
            assert output == blob

    def test_end_of_lines(self):
        output_filter = OutputFilter()
        output = output_filter.end_of_lines()
        assert output == []

    def test_run_output_filter(self):
        input_blobs = [
            {'fungo': 'dingo', 'bingo': [11, 37], 'banana': {'a': 11}},
            {'span': 'div', 'head': ['tail', 22], 'orange': {'lemmon': 'zits'}},
        ]
        self.run_test(OutputFilter, input_blobs, expected_output_blobs=input_blobs)
