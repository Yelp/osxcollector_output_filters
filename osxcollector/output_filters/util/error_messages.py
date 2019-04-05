# -*- coding: utf-8 -*-
#
# A set of simple methods for writing messages to stderr
#
from __future__ import absolute_import
from __future__ import unicode_literals

import sys
from traceback import extract_tb
from traceback import format_list


def write_exception(e):
    exc_type, _, exc_traceback = sys.exc_info()
    msg = ', '.join(str(a) for a in e.args)
    sys.stderr.write('[ERROR] {0} {1}\n'.format(exc_type.__name__, msg))
    for line in format_list(extract_tb(exc_traceback)):
        sys.stderr.write(line)


def write_error_message(message):
    sys.stderr.write('[ERROR] ')
    sys.stderr.write(message)
    sys.stderr.write('\n')
