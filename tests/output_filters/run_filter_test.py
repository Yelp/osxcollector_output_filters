# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

import simplejson
from mock import patch
from six import StringIO

from osxcollector.output_filters.base_filters.output_filter import _run_filter


class RunFilterTest:

    def run_test(self, create_filter, input_blobs=None, expected_output_blobs=None):
        """Mocks out stdin, stdout, and config then runs input lines through an OutputFilter.

        Args:
            create_filter: A callable that returns an OutputFilter.
            input_blobs: An array of dicts to pass to OutputFilter. These will be serialized into strings and passed as stdin.
            expected_output_blobs: An array of dicts the output of the OutputFilter must match.
        """
        if not input_blobs:
            input_blobs = []
        input_lines = '\n'.join([simplejson.dumps(blob) for blob in input_blobs])

        with patch(
            'sys.stdin', StringIO(input_lines),
        ), patch(
            'sys.stdout', new_callable=StringIO,
        ) as mock_stdout, patch(
            'osxcollector.output_filters.util.config._config_file_path',
            return_value='./tests/output_filters/data/test_osxcollector_config.yaml',
        ):
            output_filter = create_filter()
            _run_filter(output_filter)
            output_lines = [line for line in mock_stdout.getvalue().split('\n') if len(line)]
            output_blobs = [simplejson.loads(line) for line in output_lines]

            if expected_output_blobs:
                assert len(output_blobs) == len(expected_output_blobs)

                for expected_blob, actual_blob in zip(expected_output_blobs[1:], output_blobs[1:]):
                    assert_equal_sorted(expected_blob, actual_blob)

            return output_blobs

    def assert_key_added_to_blob(self, added_key, expected_values, input_blobs, output_blobs):
        """Verifies that a single key has been added to each input_blob with an expected value.

        Asserts that effectively:
        output_blobs = [input_blob.update(key=expected_value) for expected_value, input_blob in zip(expected_values, input_blobs)]

        Args:
            added_key: The name of the key that should have been added.
            expected_values: A list containing the expected value of the key for each input_blob
            input_blobs: A list of dicts that were the initial input.
            output_blobs: A list of dicts that are the output.
        """

        if expected_values:
            actual_values = list(blob.get(added_key, None) for blob in output_blobs)
            for actual, expected in zip(actual_values, expected_values):
                assert_equal_sorted(actual, expected)

        # Minus the added key, the input should be unchanged
        for input_blob, output_blob in zip(input_blobs, output_blobs):
            if added_key in output_blob:
                del output_blob[added_key]
            assert_equal_sorted(input_blob, output_blob)

    def load_reports(self, filename):
        with open(filename, 'r') as fp:
            file_contents = fp.read()
            reports = simplejson.loads(file_contents)
        return reports


def assert_equal_sorted(a, b):
    """A version of T.assert_equal that ignores the ordering of lists or sets.

    Args:
        a: first item to compare
        b: next time to compare
    Raises:
        assert when items don't match
    """
    assert sort_for_comparison(a) == sort_for_comparison(b)


def sort_for_comparison(val):
    """Sort the input if it is a list or dict or set, return it unchanged otherwise.

    Args:
        val: A value of any type
    Returns:
        A more easily comparable version of the input
    """
    if isinstance(val, list):
        try:
            return sorted(val)
        except Exception:
            return val
    elif isinstance(val, set):
        return sort_for_comparison(list(val))
    elif isinstance(val, dict):
        for key in val:
            val[key] = sort_for_comparison(val[key])
        return val
    else:
        return val
