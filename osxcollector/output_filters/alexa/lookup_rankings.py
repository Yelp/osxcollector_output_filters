#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# AlexaRankingFilter uses the AWIS API to lookup Alexa traffic rankings.
#
from __future__ import absolute_import
from __future__ import unicode_literals

from threat_intel.alexaranking import AlexaRankingApi

from osxcollector.output_filters.base_filters.output_filter import run_filter_main
from osxcollector.output_filters.base_filters.threat_feed import ThreatFeedFilter
from osxcollector.output_filters.util.config import config_get_deep


class LookupRankingsFilter(ThreatFeedFilter):

    """A class to lookup traffic rankings using AWIS API."""

    def __init__(self, lookup_when=None, **kwargs):
        super(LookupRankingsFilter, self).__init__(
            'osxcollector_domains',
            'osxcollector_alexa_rank',
            lookup_when=lookup_when,
            name_of_api_key=None,
            **kwargs
        )

    def _lookup_iocs(self, domains, resource_per_req=25):
        """Caches the Alexa ranking info for a set of domains.

        Args:
            domains - a list of domains.
        Returns:
            A dict with domain as key and threat info as value
        """
        traffic_info = {}

        cache_file_name = config_get_deep('alexa.LookupRankingsFilter.cache_file_name', None)
        ar = AlexaRankingApi(resource_per_req, cache_file_name=cache_file_name)

        iocs = domains
        reports = ar.get_alexa_rankings(iocs)
        for domain in reports:
            report = reports[domain]
            if report and self._should_store_ioc_info(report):
                traffic_info[domain] = report

        return traffic_info

    def _should_store_ioc_info(self, report):
        """Only store if traffic ranking passes a certain threshold.

        Args:
            report - a dict from get_alexa_rankings
        Returns:
            booleans
        """
        # Always include Alexa ranking information since we do not yet
        # categorize by it for the output summaries, rather just use it as an
        # additional source of threat intel.
        return True


def main():
    run_filter_main(LookupRankingsFilter)


if __name__ == '__main__':
    main()
