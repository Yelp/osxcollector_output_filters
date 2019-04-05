# -*- coding: utf-8 -*-
#
# All exceptions thrown by the osxcollector.output_filters module
#
from __future__ import absolute_import
from __future__ import unicode_literals


class OutputFilterError(Exception):
    pass


class MissingConfigError(OutputFilterError):

    """An error to throw when configuration is missing"""
    pass


class BadDomainError(OutputFilterError):

    """An error to throw when a domain is invalid."""
    pass
