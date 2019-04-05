# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

import logging

# Suppress output from tldextract module
logging.getLogger('tldextract').addHandler(logging.NullHandler())
