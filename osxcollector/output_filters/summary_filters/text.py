# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

import sys
from numbers import Number

import six

from osxcollector.output_filters.summary_filters.summary import SummaryFilter


class TextSummaryFilter(SummaryFilter):
    """Prints the analysis summary (AKA "Very Readable Output") in plain text format."""

    END_COLOR = '\033[0m'
    SECTION_COLOR = '\033[1m'
    BOT_COLOR = '\033[93m\033[1m'
    KEY_COLOR = '\033[94m'
    VAL_COLOR = '\033[32m'

    def __init__(self, monochrome=False, text_output_file=None, **kwargs):
        super(TextSummaryFilter, self).__init__(summary_output_file=text_output_file, **kwargs)
        self._monochrome = monochrome

    def filter_line(self, blob):
        """Each Line of OSXCollector output will be passed to filter_line.

        The OutputFilter should return the line, either modified or unmodified.
        The OutputFilter can also choose to return nothing, effectively swallowing the line.

        Args:
            output_line: A dict

        Returns:
            A dict or None
        """
        if 'osxcollector_vthash' in blob:
            self._vthash.append(blob)

        if 'osxcollector_vtdomain' in blob:
            self._vtdomain.append(blob)

        if 'osxcollector_opendns' in blob:
            self._opendns.append(blob)

        if 'osxcollector_blacklist' in blob:
            self._blacklist.append(blob)

        if 'osxcollector_related' in blob:
            self._related.append(blob)

        if self._show_signature_chain:
            if 'signature_chain' in blob and blob['osxcollector_section'] in ['startup', 'kext']:
                signature_chain = blob['signature_chain']
                if not len(signature_chain) or 'Apple Root CA' != signature_chain[-1]:
                    self._signature_chain.append(blob)

        if self._show_browser_ext:
            if blob['osxcollector_section'] in ['firefox', 'chrome'] and blob.get('osxcollector_subsection') == 'extensions':
                self._extensions.append(blob)

        return blob

    def _write(self, msg, color=END_COLOR):
        if not self._monochrome:
            self._output_stream.write(color)
        try:
            self._output_stream.write(msg.encode('utf-8', errors='ignore'))
        except UnicodeDecodeError as err:
            self._output_stream.write(msg)
            sys.stderr.write('Unicode decode error: {0}'.format(err))
        if not self._monochrome:
            self._output_stream.write(self.END_COLOR)

    def end_of_lines(self):
        """Called after all lines have been fed to filter_output_line.

        The OutputFilter can do any batch processing on that requires the complete input.

        Returns:
            An array of dicts (empty array if no lines remain)
        """
        self._write('== Very Readable Output Bot ==\n', self.BOT_COLOR)
        self._write('Let\'s see what\'s up with this machine.\n\n', self.BOT_COLOR)

        if len(self._vthash):
            self._write('Dang! You\'ve got known malware on this machine. Hope it\'s commodity stuff\n', self.BOT_COLOR)
            self._summarize_blobs(self._vthash)
            self._write('Sheesh! This is why we can\'t have nice things!\n\n', self.BOT_COLOR)

        if len(self._vtdomain):
            self._write('I see you\'ve been visiting some \'questionable\' sites. If you trust VirusTotal that is.\n', self.BOT_COLOR)
            self._summarize_blobs(self._vtdomain)
            self._write('I hope it was worth it!\n\n', self.BOT_COLOR)

        if len(self._opendns):
            self._write('Well, here\'s some domains OpenDNS wouldn\'t recommend.\n', self.BOT_COLOR)
            self._summarize_blobs(self._opendns)
            self._write('You know you shouldn\'t just click every link you see? #truth\n\n', self.BOT_COLOR)

        if len(self._blacklist):
            self._write('We put stuff on a blacklist for a reason. Mostly so you don\'t do this.\n', self.BOT_COLOR)
            self._summarize_blobs(self._blacklist)
            self._write('SMH\n\n', self.BOT_COLOR)

        if len(self._related):
            self._write('This whole things started with just a few clues. Now look what I found.\n', self.BOT_COLOR)
            self._summarize_blobs(self._related)
            self._write('Nothing hides from Very Readable Output Bot\n\n', self.BOT_COLOR)

        if len(self._signature_chain):
            self._write('If these binaries were signed by \'Apple Root CA\' I\'d trust them more.\n', self.BOT_COLOR)
            self._summarize_blobs(self._signature_chain)
            self._write('Let\'s just try and stick with some safe software\n\n', self.BOT_COLOR)

        if len(self._extensions):
            self._write('Let\'s see what\'s hiding in the browser, shall we.\n', self.BOT_COLOR)
            self._summarize_blobs(self._extensions)
            self._write('You know these things have privileges galore.\n\n', self.BOT_COLOR)

        if len(self._add_to_blacklist):
            self._add_to_blacklist = list(set(self._add_to_blacklist))
            self._write('If I were you, I\'d probably update my blacklists to include:\n', self.BOT_COLOR)
            for key, val in self._add_to_blacklist:
                self._summarize_val(key, val)
            self._write('That might just help things, Skippy!\n\n', self.BOT_COLOR)

        self._write('== Very Readable Output Bot ==\n', self.BOT_COLOR)
        self._write('#kaythanksbye', self.BOT_COLOR)

        return []

    def _summarize_blobs(self, blobs):
        for blob in blobs:
            self._summarize_line(blob)

            add_to_blacklist = False

            if 'osxcollector_vthash' in blob:
                self._summarize_vthash(blob)
                add_to_blacklist = True

            if 'osxcollector_vtdomain' in blob:
                self._summarize_vtdomain(blob)

            if 'osxcollector_opendns' in blob:
                self._summarize_opendns(blob)

            if 'osxcollector_blacklist' in blob:
                for key in blob['osxcollector_blacklist']:
                    self._summarize_val('blacklist-{0}'.format(key), blob['osxcollector_blacklist'][key])

            if 'osxcollector_related' in blob:
                for key in blob['osxcollector_related']:
                    self._summarize_val('related-{0}'.format(key), blob['osxcollector_related'][key])

            if 'md5' in blob and '' == blob['md5']:
                add_to_blacklist = True

            if add_to_blacklist:
                blacklists = blob.get('osxcollector_blacklist', {})
                values_on_blacklist = blacklists.get('hashes', [])
                for key in ['md5', 'sha1', 'sha2']:
                    val = blob.get(key, '')
                    if len(val) and val not in values_on_blacklist:
                        self._add_to_blacklist.append((key, val))

                values_on_blacklist = blacklists.get('domains', [])
                for domain in blob.get('osxcollector_domains', []):
                    if domain not in values_on_blacklist:
                        self._add_to_blacklist.append(('domain', domain))

    def _summarize_line(self, blob):
        section = blob.get('osxcollector_section')
        subsection = blob.get('osxcollector_subsection', '')

        self._write('- {0} {1}\n'.format(section, subsection), self.SECTION_COLOR)
        for key in sorted(blob.keys()):
            if not key.startswith('osxcollector') and blob.get(key):
                val = blob.get(key)
                self._summarize_val(key, val)

    def _summarize_vthash(self, blob):
        for blob in blob['osxcollector_vthash']:
            for key in ['positives', 'total', 'scan_date', 'permalink']:
                val = blob.get(key)
                self._summarize_val(key, val, 'vthash')

    def _summarize_vtdomain(self, blob):
        for blob in blob['osxcollector_vtdomain']:
            for key in ['domain', 'detections']:
                val = blob.get(key)
                self._summarize_val(key, val, 'vtdomain')

    def _summarize_opendns(self, blob):
        for blob in blob['osxcollector_opendns']:
            for key in ['domain', 'categorization', 'security', 'link']:
                val = blob.get(key)
                self._summarize_val(key, val, 'opendns')

    def _summarize_val(self, key, val, prefix=None):
        self._print_key(key, prefix)
        self._print_val(val)
        self._write('\n')

    def _print_key(self, key, prefix):
        if not prefix:
            prefix = ''
        else:
            prefix += '-'

        self._write('  {0}{1}'.format(prefix, key), self.KEY_COLOR)
        self._write(': ')

    def _print_val(self, val):
        if isinstance(val, list):
            self._write('[')
            for index, elem in enumerate(val):
                self._print_val(elem)
                if index != len(val) - 1:
                    self._write(', ')
            self._write(']')
        elif isinstance(val, dict):
            self._write('{')
            for index, key in enumerate(val):
                self._write('"')
                self._write(key, self.VAL_COLOR)
                self._write('": ')
                self._print_val(val[key])
                if index != len(val) - 1:
                    self._write(', ')
            self._write('}')
        elif isinstance(val, six.string_types):
            val = val[:480]
            self._write('"')
            self._write(val, self.VAL_COLOR)
            self._write('"')
        elif isinstance(val, Number):
            self._write('{0}'.format(val), self.VAL_COLOR)
