# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

from osxcollector.output_filters.exceptions import BadDomainError
from osxcollector.output_filters.util.error_messages import write_error_message
from osxcollector.output_filters.util.error_messages import write_exception


class TestWriteException:

    def test_simple_exception(self, capsys):
        try:
            raise Exception()
        except Exception as e:
            write_exception(e)

        output = capsys.readouterr().err
        assert 0 == output.find('[ERROR]')

    def test_specific_exception(self, capsys):
        try:
            raise BadDomainError()
        except Exception as e:
            write_exception(e)

        output = capsys.readouterr().err
        assert output.find('[ERROR] BadDomainError') == 0

    def test_exception_message(self, capsys):
        try:
            raise BadDomainError('Look for me in validation')
        except Exception as e:
            write_exception(e)

        output = capsys.readouterr().err
        assert output.find('[ERROR] BadDomainError Look for me in validation') == 0


class TestWriteErrorMessage:

    def test_write_error_message(self, capsys):
        message = 'Look for me in validation'
        expected = '[ERROR] Look for me in validation\n'

        write_error_message(message)

        output = capsys.readouterr().err
        assert output == expected
