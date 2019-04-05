#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# The AnalyzeFilter is a handy little tool that ties together many filters to attempt to
# enhance the output of OSXCollector with data from threat APIs, compare against blacklists,
# search for lines related to suspicious domains, ips, or files, and generally figure shit out.
#
# The more detailed description of what goes on:
#  1. Parse out browser extension information.
#  2. Find all the domains in every line. Add them to the output lines.
#  3. Find any file hashes or domains that are on blacklists. Mark those lines.
#  4. Take any filepaths from the command line and mark all lines related to those.
#  5. Take any domain or IP from the command line and use OpenDNS Investigate API to find all the domains
#     related to those domains and all the domains related to those related domains - basically the 1st and 2nd
#     generation related domains. Mark any lines where these domains appear.
#  6. Lookup all sha1 hashes in ShadowServer's bin-test whitelist.
#     Files that match both hash and filename are ignored by further filters.
#  7. Lookup file hashes in VirusTotal and mark any lines with suspicious files hashes.
#  8. Lookup all the domains in the file with OpenDNS Investigate. Categorize and score the domains.
#     Mark all the lines that contain domains that were scored as "suspicious".
#  9. Lookup suspicious domains, those domains on a blacklist, or those related to the initial input in VirusTotal.
# 10. Cleanup the browser history and sort it in descending time order.
# 11. Save all the enhanced output to a new file.
# 12. Look at all the interesting lines in the file and try to summarize them in some very human readable output.
# 13. Party!
#
from __future__ import absolute_import
from __future__ import unicode_literals

from argparse import ArgumentParser

from osxcollector.output_filters.alexa.lookup_rankings import LookupRankingsFilter as ArLookupRankingsFilter
from osxcollector.output_filters.base_filters.chain import ChainFilter
from osxcollector.output_filters.base_filters.output_filter import run_filter_main
from osxcollector.output_filters.chrome.find_extensions import FindExtensionsFilter as ChromeExtensionsFilter
from osxcollector.output_filters.chrome.sort_history import SortHistoryFilter as ChromeHistoryFilter
from osxcollector.output_filters.find_blacklisted import FindBlacklistedFilter
from osxcollector.output_filters.find_domains import FindDomainsFilter
from osxcollector.output_filters.firefox.find_extensions import FindExtensionsFilter as FirefoxExtensionsFilter
from osxcollector.output_filters.firefox.sort_history import SortHistoryFilter as FirefoxHistoryFilter
from osxcollector.output_filters.opendns.lookup_domains import LookupDomainsFilter as OpenDnsLookupDomainsFilter
from osxcollector.output_filters.opendns.related_domains import RelatedDomainsFilter as OpenDnsRelatedDomainsFilter
from osxcollector.output_filters.related_files import RelatedFilesFilter
from osxcollector.output_filters.shadowserver.lookup_hashes import LookupHashesFilter as ShadowServerLookupHashesFilter
from osxcollector.output_filters.summary_filters.html import HtmlSummaryFilter
from osxcollector.output_filters.summary_filters.text import TextSummaryFilter
from osxcollector.output_filters.virustotal.lookup_domains import LookupDomainsFilter as VtLookupDomainsFilter
from osxcollector.output_filters.virustotal.lookup_hashes import LookupHashesFilter as VtLookupHashesFilter


class AnalyzeFilter(ChainFilter):

    """AnalyzeFilter chains all the other filters to produce maximum effect.

    A lot of the smarts of AnalyzeFilter are around what filters to run in which order and how results of one filter should
    effect the operations of the next filter.
    """

    def __init__(
        self, no_opendns=False, no_virustotal=False, no_shadowserver=False,
        no_alexa=False, readout=False, **kwargs
    ):

        filter_chain = []

        if not readout:
            filter_chain.append(ChromeExtensionsFilter(**kwargs))
            filter_chain.append(FirefoxExtensionsFilter(**kwargs))

            filter_chain.append(FindDomainsFilter(**kwargs))

            # Do Alexa ranking lookups first since they are dependent only on FindDomainsFilter
            if not no_alexa:
                filter_chain.append(ArLookupRankingsFilter(**kwargs))

            # Do hash related lookups first. This is done first since hash lookup is not influenced
            # by anything but other hash lookups.
            if not no_shadowserver:
                filter_chain.append(ShadowServerLookupHashesFilter(**kwargs))
            if not no_virustotal:
                filter_chain.append(
                    VtLookupHashesFilter(lookup_when=AnalyzeFilter.lookup_when_not_in_shadowserver, **kwargs),
                )

            # Find blacklisted stuff next. Finding blacklisted domains requires running FindDomainsFilter first.
            filter_chain.append(FindBlacklistedFilter(**kwargs))

            # RelatedFilesFilter and OpenDnsRelatedDomainsFilter use command line args in addition to previous filter
            # results to find lines of interest.
            filter_chain.append(RelatedFilesFilter(when=AnalyzeFilter.find_related_when, **kwargs))
            if not no_opendns:
                filter_chain.append(
                    OpenDnsRelatedDomainsFilter(related_when=AnalyzeFilter.find_related_when, **kwargs),
                )

            # Lookup threat info on suspicious and related stuff
            if not no_opendns:
                filter_chain.append(
                    OpenDnsLookupDomainsFilter(lookup_when=AnalyzeFilter.lookup_when_not_in_shadowserver, **kwargs),
                )
            if not no_virustotal:
                filter_chain.append(
                    VtLookupDomainsFilter(lookup_when=AnalyzeFilter.lookup_domains_in_vt_when, **kwargs),
                )

            # Sort browser history for maximum pretty
            filter_chain.append(FirefoxHistoryFilter(**kwargs))
            filter_chain.append(ChromeHistoryFilter(**kwargs))

            filter_chain.append(TextSummaryFilter(**kwargs))
            filter_chain.append(HtmlSummaryFilter(**kwargs))

        super(AnalyzeFilter, self).__init__(filter_chain, **kwargs)

    def _on_get_argument_parser(self):
        """Returns an ArgumentParser with arguments for just this OutputFilter (not the contained chained OutputFilters).

        Returns:
            An `argparse.ArgumentParser`
        """
        parser = ArgumentParser()
        group = parser.add_argument_group('AnalyzeFilter')
        group.add_argument(
            '--readout', dest='readout', action='store_true', default=False,
            help='[OPTIONAL] Skip the analysis and just output really readable analysis',
        )
        group.add_argument(
            '--no-opendns', dest='no_opendns', action='store_true', default=False,
            help='[OPTIONAL] Don\'t run OpenDNS filters',
        )
        group.add_argument(
            '--no-virustotal', dest='no_virustotal', action='store_true', default=False,
            help='[OPTIONAL] Don\'t run VirusTotal filters',
        )
        group.add_argument(
            '--no-shadowserver', dest='no_shadowserver', action='store_true', default=False,
            help='[OPTIONAL] Don\'t run ShadowServer filters',
        )
        group.add_argument(
            '--no-alexa', dest='no_alexa', action='store_true', default=False,
            help='[OPTIONAL] Don\'t run AlexaRanking filters',
        )
        group.add_argument(
            '-M', '--monochrome', dest='monochrome', action='store_true', default=False,
            help='[OPTIONAL] Output monochrome analysis',
        )
        group.add_argument(
            '--show-signature-chain', dest='show_signature_chain', action='store_true', default=False,
            help='[OPTIONAL] Output unsigned startup items and kexts.',
        )
        group.add_argument(
            '--show-browser-ext', dest='show_browser_ext', action='store_true', default=False,
            help='[OPTIONAL] Output the list of installed browser extensions.',
        )
        group.add_argument(
            '-t', '--text', dest='text_output_file', default=None,
            help='[OPTIONAL] Path to the output file where summary in plain text format will be written to.',
        )
        group.add_argument(
            '-w', '--html', dest='html_output_file', default=None,
            help='[OPTIONAL] Path to the output file where summary in HTML format will be written to.',
        )
        group.add_argument(
            '-c', '--group-by-iocs', dest='group_by_iocs', action='store_true', default=False,
            help='[OPTIONAL] Summarize the output grouped by IOCs instead of by threat indicators.',
        )
        group.add_argument(
            '-k', '--group-key', dest='group_key', default=None,
            help='[OPTIONAL] If sorting by IOCs, select which key to group by (sha1/sha2/domain)',
        )
        return parser

    @staticmethod
    def include_in_summary(blob):
        _KEYS_FOR_SUMMARY = [
            'osxcollector_vthash',
            'osxcollector_vtdomain',
            'osxcollector_opendns',
            'osxcollector_blacklist',
            'osxcollector_related',
        ]

        return any([key in blob for key in _KEYS_FOR_SUMMARY])

    @staticmethod
    def lookup_when_not_in_shadowserver(blob):
        """ShadowServer whitelists blobs that can be ignored."""
        return 'osxcollector_shadowserver' not in blob

    @staticmethod
    def lookup_domains_in_vt_when(blob):
        """VT domain lookup is a final step and what to lookup is dependent upon what has been found so far."""
        return AnalyzeFilter.lookup_when_not_in_shadowserver(blob) and AnalyzeFilter.include_in_summary(blob)

    @staticmethod
    def find_related_when(blob):
        """When to find related terms or domains.

        Stuff in ShadowServer is not interesting.
        Blacklisted file paths are worth investigating.
        Files where the md5 could not be calculated are also interesting. Root should be able to read files.
        Files with a bad hash in VT are obviously malware, go find related bad stuff.

        Args:
            blob - a line of output from OSXCollector
        Returns:
            boolean
        """
        if 'osxcollector_shadowserver' in blob:
            return False
        if '' == blob.get('md5', None):
            return True
        return any([key in blob for key in ['osxcollector_vthash', 'osxcollector_related']])


def main():
    run_filter_main(AnalyzeFilter)


if __name__ == '__main__':
    main()
