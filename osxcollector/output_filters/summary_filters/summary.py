# -*- coding: utf-8 -*-
import sys

from osxcollector.output_filters.base_filters.output_filter import OutputFilter


class SummaryFilter(OutputFilter):
    """Base class for summary filters."""

    def __init__(self, show_signature_chain=False, show_browser_ext=False, summary_output_file=None, **kwargs):
        super(SummaryFilter, self).__init__(**kwargs)
        self._vthash = []
        self._vtdomain = []
        self._opendns = []
        self._blacklist = []
        self._related = []
        self._signature_chain = []
        self._extensions = []
        self._show_signature_chain = show_signature_chain
        self._show_browser_ext = show_browser_ext

        self._add_to_blacklist = []

        self._summary_output_file = summary_output_file

        self._output_stream = open(summary_output_file, 'w') if summary_output_file else sys.stdout

    def __del__(self):
        if self._summary_output_file:
            self._output_stream.close()
