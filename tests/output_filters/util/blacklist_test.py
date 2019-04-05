# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

from copy import deepcopy

import pytest
from mock import call
from mock import patch

from osxcollector.output_filters.exceptions import MissingConfigError
from osxcollector.output_filters.util.blacklist import Blacklist
from osxcollector.output_filters.util.blacklist import create_blacklist


class TestCreateBlacklist:

    @pytest.fixture(scope='function', autouse=True)
    def file_contents(self):
        file_contents = [
            # Fruits
            'apple', 'banana',

            # Cars
            'corolla', 'datsun',
        ]
        with patch.object(
            Blacklist, '_read_blacklist_file_contents', return_value=file_contents,
        ) as file_contents:
            yield file_contents

    @pytest.fixture(scope='function')
    def blacklist_data(self):
        yield {
            'blacklist_name': 'only_required',
            'blacklist_keys': ['fruit_name'],
            'blacklist_file_path': '/who/cares/I/mock/this.txt',
        }

    def test_only_required_keys(self, blacklist_data):
        blacklist = create_blacklist(blacklist_data)
        assert blacklist.name == blacklist_data['blacklist_name']
        assert blacklist._blacklisted_keys == blacklist_data['blacklist_keys']
        assert not blacklist._is_regex
        assert not blacklist._is_domains

    def test_missing_required_keys(self, blacklist_data):
        for key in blacklist_data:
            _blacklist_data = deepcopy(blacklist_data)
            del _blacklist_data[key]
            with pytest.raises(MissingConfigError):
                create_blacklist(_blacklist_data)

    def test_required_with_two_keys(self, blacklist_data):
        blacklist_data['blacklist_keys'] = ['fruit_name', 'car_name']
        blacklist = create_blacklist(blacklist_data)
        assert blacklist._blacklisted_keys == blacklist_data['blacklist_keys']

    def test_keys_not_list(self, blacklist_data):
        blacklist_data['blacklist_keys'] = 'fruit_name'
        with pytest.raises(MissingConfigError):
            create_blacklist(blacklist_data)

    def test_is_regex(self, blacklist_data):
        blacklist_data['blacklist_is_regex'] = True
        blacklist = create_blacklist(blacklist_data)
        assert blacklist._is_regex

    def test_is_domains(self, blacklist_data, file_contents):
        file_contents.return_value = ['apple.com', 'banana.org']
        # Setting 'blacklist_is_domains' overrides 'blacklist_is_regex'
        blacklist_data['blacklist_is_domains'] = True
        blacklist_data['blacklist_is_regex'] = False
        blacklist = create_blacklist(blacklist_data)
        assert blacklist._is_regex
        assert blacklist._is_domains

    # TODO: Refactor OSXCollector Output Filters to work with unicode-based domains
    def test_bad_domains_unicode(self, blacklist_data):
        unicode_domain_1 = 'yelp.公司'
        unicode_domain_2 = 'www.Yülp.tld'
        unicode_domain_3 = 'иelф.р'
        unicode_domains = [unicode_domain_1, unicode_domain_2, unicode_domain_3]
        blacklist_data['blacklist_is_domains'] = True
        with patch.object(
            Blacklist, '_read_blacklist_file_contents',
            return_value=unicode_domains,
        ):
            with patch('logging.warning', autospec=True) as patched_logging_warning:
                create_blacklist(blacklist_data)
                assert patched_logging_warning.call_count == 3

        calls = [
            call(
                u'Blacklisted value "{0}" cannot be resolved as a domain name'
                .format(unicode_domain),
            ) for unicode_domain in unicode_domains
        ]
        assert calls == patched_logging_warning.call_args_list

    def test_bad_domains(self, blacklist_data):
        blacklist_data['blacklist_is_domains'] = True
        with patch('logging.warning', autospec=True) as patched_logging_warning:
            blacklist = create_blacklist(blacklist_data)
            assert patched_logging_warning.call_count == 4
            calls = [
                call('Blacklisted value "apple" cannot be resolved as a domain name'),
                call('Blacklisted value "banana" cannot be resolved as a domain name'),
                call('Blacklisted value "corolla" cannot be resolved as a domain name'),
                call('Blacklisted value "datsun" cannot be resolved as a domain name'),
            ]
            assert calls == patched_logging_warning.call_args_list

        blob = {'fruit_name': 'apple.com'}
        assert not blacklist.match_line(blob)

    def test_match_fruit(self, blacklist_data):
        good_blobs = [
            {'fruit_name': 'apple'},
            {'fruit_name': 'banana'},
        ]
        bad_blobs = [
            {'car_name': 'corolla'},
            {'car_name': 'datsun'},
        ]

        blacklist = create_blacklist(blacklist_data)
        for blob in good_blobs:
            assert blacklist.match_line(blob)
        for blob in bad_blobs:
            assert not blacklist.match_line(blob)

    def test_match_fruit_and_cars(self, blacklist_data):
        good_blobs = [
            {'fruit_name': 'apple'},
            {'fruit_name': 'banana'},
            {'car_name': 'corolla'},
            {'car_name': 'datsun'},
        ]

        blacklist_data['blacklist_keys'] = ['fruit_name', 'car_name']
        blacklist = create_blacklist(blacklist_data)
        for blob in good_blobs:
            assert blacklist.match_line(blob)

    def test_match_fruit_regex(self, blacklist_data, file_contents):
        good_blobs = [
            {'fruit_name': 'apple'},
        ]

        bad_blobs = [
            {'fruit_name': 'banana'},
            {'car_name': 'corolla'},
            {'car_name': 'datsun'},
        ]

        blacklist_data['blacklist_is_regex'] = True
        file_contents.return_value = ['app.*', 'ban.+org']
        blacklist = create_blacklist(blacklist_data)
        for blob in good_blobs:
            assert blacklist.match_line(blob)
        for blob in bad_blobs:
            assert not blacklist.match_line(blob)

    def test_match_domains(self, blacklist_data, file_contents):
        good_blobs = [
            {'fruit_name': 'apple.com'},
            {'fruit_name': 'www.apple.com'},
            {'fruit_name': 'www.another-thing.apple.com'},
        ]

        bad_blobs = [
            {'fruit_name': 'cran-apple.com'},
            {'fruit_name': 'apple.org'},
            {'fruit_name': 'apple.com.jp'},
            {'car_name': 'apple.com'},
        ]
        blacklist_data['blacklist_is_domains'] = True
        file_contents.return_value = ['apple.com']
        blacklist = create_blacklist(blacklist_data)
        for blob in good_blobs:
            assert blacklist.match_line(blob)
        for blob in bad_blobs:
            assert not blacklist.match_line(blob)

    # TODO: Refactor OSXCollector Output Filters to work with unicode-based domains
    def test_log_unicode_domain(self):
        config_chunk = {
            'blacklist_name': 'Unicode domain',
            'blacklist_keys': ['visited_domain'],
            'blacklist_file_path': 'not_really_a_blacklist.txt',
            'blacklist_is_domains': True,
        }
        file_contents = ['Bücher.tld', 'yelp.公司', 'www.Yülp.tld', 'иelф.р']
        with patch.object(
            Blacklist, '_read_blacklist_file_contents', return_value=file_contents,
        ), patch('logging.warning', autospec=True) as patched_logging_warning:
            blacklist = create_blacklist(config_chunk)
            assert patched_logging_warning.call_count == 4
            calls = [
                call(
                    u'Blacklisted value "{0}" cannot be resolved as a domain name'
                    .format(domain),
                ) for domain in file_contents
            ]
            assert calls == patched_logging_warning.call_args_list

        blob = {'visted_domain': 'Bücher.tld'}
        assert not blacklist.match_line(blob)
