# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

import sys
from collections import defaultdict

import six

from osxcollector.output_filters.base_filters.output_filter import OutputFilter


class SummaryFilter(OutputFilter):
    """Base class for summary filters."""

    def __init__(self, show_signature_chain=False, show_browser_ext=False, summary_output_file=None, group_by_iocs=False, group_key=None, **kwargs):
        super(SummaryFilter, self).__init__(**kwargs)
        self._iocs = []
        self._iocs_by_key = defaultdict(list)
        self._vthash = []
        self._vtdomain = []
        self._opendns = []
        self._alexarank = []
        self._blacklist = []
        self._related = []
        self._signature_chain = []
        self._extensions = []
        self._show_signature_chain = show_signature_chain
        self._show_browser_ext = show_browser_ext
        self._group_by_iocs = group_by_iocs
        self._group_key = group_key

        self._add_to_blacklist = []

        self._close_file = False

        self._open_output_stream(summary_output_file)

    def _open_output_stream(self, summary_output_file):
        if summary_output_file:
            if isinstance(summary_output_file, six.string_types):
                self._output_stream = open(summary_output_file, 'w')
                self._close_file = True
            else:
                # not a string, most likely already opened output stream
                self._output_stream = summary_output_file
        else:
            self._output_stream = sys.stdout

    def __del__(self):
        self._close_output_stream()

    def _close_output_stream(self):
        if self._close_file:
            self._output_stream.close()
