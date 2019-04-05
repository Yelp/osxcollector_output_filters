# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals


class DictUtils(object):

    """A set of method for manipulating dictionaries."""

    @classmethod
    def _link_path_to_chain(cls, path):
        """Helper method for get_deep

        Args:
            path: A str representing a chain of keys separated '.' or an enumerable set of strings
        Returns:
            an enumerable set of strings
        """
        if path == '':
            return []
        elif type(path) in (list, tuple, set):
            return path
        else:
            return path.split('.')

    @classmethod
    def _get_deep_by_chain(cls, x, chain, default=None):
        """Grab data from a dict using a ['key1', 'key2', 'key3'] chain param to do deep traversal.

        Args:
            x: A dict
            chain: an enumerable set of strings
            default: A value to return if the path can not be found
        Returns:
            The value of the key or default
        """
        if chain == []:
            return default
        try:
            for link in chain:
                try:
                    x = x[link]
                except (KeyError, TypeError):
                    x = x[int(link)]
        except (KeyError, TypeError, ValueError):
            x = default
        return x

    @classmethod
    def get_deep(cls, x, path='', default=None):
        """Grab data from a dict using a 'key1.key2.key3' path param to do deep traversal.

        Args:
            x: A dict
            path: A 'deep path' to retrieve in the dict
            default: A value to return if the path can not be found
        Returns:
            The value of the key or default
        """
        chain = cls._link_path_to_chain(path)
        return cls._get_deep_by_chain(x, chain, default=default)
