#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# LookupHashesFilter uses ShadowServer to lookup the values in 'sha1' and add 'osxcollector_shadowserver' key.
#
from __future__ import absolute_import
from __future__ import unicode_literals

import os.path

from threat_intel.shadowserver import ShadowServerApi

from osxcollector.output_filters.base_filters.output_filter import run_filter_main
from osxcollector.output_filters.base_filters.threat_feed import ThreatFeedFilter
from osxcollector.output_filters.util.config import config_get_deep


class LookupHashesFilter(ThreatFeedFilter):

    """A class to lookup hashes using ShadowServer API."""

    def __init__(self, lookup_when=None, **kwargs):
        super(LookupHashesFilter, self).__init__('sha1', 'osxcollector_shadowserver', lookup_when=lookup_when, **kwargs)

    def _lookup_iocs(self, all_iocs):
        """Looks up the ShadowServer info for a set of hashes.

        Args:
            all_iocs - a list of hashes.
        Returns:
            A dict with hash as key and threat info as value
        """
        cache_file_name = config_get_deep('shadowserver.LookupHashesFilter.cache_file_name', None)
        ss = ShadowServerApi(cache_file_name=cache_file_name)
        return ss.get_bin_test(all_iocs)

    def _should_add_threat_info_to_blob(self, blob, threat_info):
        """Only add info from ShadowServer if the hash and the filename match.

        Args:
            blob - A dict of data representing a line of output from OSXCollector
            threat_info - The threat info from ShadowServer
        Returns:
            boolean
        """
        blob_filename = os.path.split(blob.get('file_path', ''))[-1]
        return blob_filename == threat_info.get('filename', '')


def main():
    run_filter_main(LookupHashesFilter)


if __name__ == '__main__':
    main()
