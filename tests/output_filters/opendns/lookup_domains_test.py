# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

import simplejson
from mock import patch
from threat_intel.opendns import InvestigateApi

from osxcollector.output_filters.opendns.lookup_domains import LookupDomainsFilter
from tests.output_filters.run_filter_test import RunFilterTest


class TestLookupDomainsFilter(RunFilterTest):

    def test_no_domains(self):
        input_blobs = [
            {'fungo': 'dingo', 'bingo': [11, 37], 'banana': {'a': 11}},
            {'span': 'div', 'head': ['tail', 22], 'orange': {'lemmon': 'zits'}},
        ]

        self.run_test(LookupDomainsFilter, input_blobs=input_blobs, expected_output_blobs=input_blobs)

    def _read_json(self, file_name):
        with(open(file_name, 'r')) as fp:
            contents = fp.read()
            return simplejson.loads(contents)

    def test_no_security_information(self):
        input_blobs = [
            {'osxcollector_domains': ['bingo.com', 'dingo.com', 'bango.com', 'dango.com'], 'banana': {'a': 11}},
        ]
        file_name_pattern = 'tests/output_filters/data/opendns/lookup_domains/{0}'
        categorization = self._read_json(file_name_pattern.format('categorization.json'))
        security = self._read_json(file_name_pattern.format('security.json'))

        with patch.object(
            InvestigateApi, 'categorization', autospec=True,
            return_value=categorization,
        ), patch.object(
            InvestigateApi, 'security', autospec=True, return_value=security,
        ):
            output_blobs = self.run_test(LookupDomainsFilter, input_blobs=input_blobs)

        expected_categorization = self._read_json(file_name_pattern.format('expected.json'))
        self.assert_key_added_to_blob('osxcollector_opendns', expected_categorization, input_blobs, output_blobs)
