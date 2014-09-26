import contextlib
import errno
from StringIO import StringIO

import mock
from oslo.config import cfg

from quark.agent import version_control
from quark.agent.xapi import VIF
from quark.tests import test_base


class TestOpenCreateRead(test_base.TestBase):
    PATH = "foobar"

    def test_open_fail_create_fail(self):
        with mock.patch("__builtin__.open") as m_open:
            m_open.side_effect = IOError(errno.ENOENT, "fail")
            with self.assertRaises(IOError):
                version_control._open_or_create_file_for_reading(self.PATH)
                m_open.assert_has_calls([mock.call(self.PATH, "rb"),
                                         mock.call(self.PATH, "wb+")])

    def test_open_fail_other_error(self):
        with mock.patch("__builtin__.open") as m_open:
            with self.assertRaises(IOError):
                m_open.side_effect = IOError(errno.EPERM, "fail")
                version_control._open_or_create_file_for_reading(self.PATH)
                m_open.assert_called_once_with(self.PATH, "rb")

    def test_open_fail_create_success(self):
        with contextlib.nested(
            mock.patch("__builtin__.open"),
            mock.patch("quark.agent.version_control.json")
        ) as (m_open, m_json):
            expected_file = mock.MagicMock()
            m_open.side_effect = (IOError(errno.ENOENT, "fail"), expected_file)
            file = version_control._open_or_create_file_for_reading(self.PATH)
            m_open.assert_has_calls([mock.call(self.PATH, "rb"),
                                     mock.call(self.PATH, "wb+")])
            self.assertEqual(expected_file, file)
            m_json.dump.assert_called_once_with({}, expected_file)
            expected_file.seek.assert_called_once_with(0)

    def test_open_success(self):
        with mock.patch("__builtin__.open") as m_open:
            file = version_control._open_or_create_file_for_reading(self.PATH)
            m_open.assert_called_once_with(self.PATH, "rb")
            self.assertEqual(m_open.return_value, file)


class TestVersionControl(test_base.TestBase):
    def setUp(self):
        self.FILEPATH = "foo_bar_path"
        cfg.CONF.set_override("version_control_path", self.FILEPATH, "AGENT")
        self.version_control = version_control.VersionControl()

    def test_diff_empty_file_empty_new_security_groups(self):
        o_fn = "quark.agent.version_control._open_or_create_file_for_reading"
        with mock.patch(o_fn) as m_open:
            m_open.return_value = StringIO("{}")
            added, updated, removed = self.version_control.diff({})
            m_open.assert_called_once_with(self.FILEPATH)
            self.assertEqual(added, [])
            self.assertEqual(updated, [])
            self.assertEqual(removed, [])

    def test_diff_empty_file_added_new_security_groups(self):
        o_fn = "quark.agent.version_control._open_or_create_file_for_reading"
        with mock.patch(o_fn) as m_open:
            m_open.return_value = StringIO("{}")
            added, updated, removed = self.version_control.diff({
                VIF("1", "2"): "foo"})
            m_open.assert_called_once_with(self.FILEPATH)
            self.assertEqual(added, [VIF("1", "2")])
            self.assertEqual(updated, [])
            self.assertEqual(removed, [])

    def test_diff_nonempty_file_added_new_security_groups(self):
        o_fn = "quark.agent.version_control._open_or_create_file_for_reading"
        with mock.patch(o_fn) as m_open:
            m_open.return_value = StringIO('{"3.4": "bar"}')
            added, updated, removed = self.version_control.diff({
                VIF("1", "2"): "baz",
                VIF("3", "4"): "bar"
            })
            m_open.assert_called_once_with(self.FILEPATH)
            self.assertEqual(added, [VIF("1", "2")])
            self.assertEqual(updated, [])
            self.assertEqual(removed, [])

    def test_diff_nonempty_file_updated_new_security_groups(self):
        o_fn = "quark.agent.version_control._open_or_create_file_for_reading"
        with mock.patch(o_fn) as m_open:
            m_open.return_value = StringIO('{"3.4": "bar"}')
            added, updated, removed = self.version_control.diff({
                VIF("3", "4"): "baz"
            })
            m_open.assert_called_once_with(self.FILEPATH)
            self.assertEqual(added, [])
            self.assertEqual(updated, [VIF("3", "4")])
            self.assertEqual(removed, [])

    def test_diff_nonempty_file_removed_new_security_groups(self):
        o_fn = "quark.agent.version_control._open_or_create_file_for_reading"
        with mock.patch(o_fn) as m_open:
            m_open.return_value = StringIO('{"3.4": "bar"}')
            added, updated, removed = self.version_control.diff({})
            m_open.assert_called_once_with(self.FILEPATH)
            self.assertEqual(added, [])
            self.assertEqual(updated, [])
            self.assertEqual(removed, [VIF("3", "4")])

    def test_diff_nonempty_file_all_kinds_new_security_groups(self):
        o_fn = "quark.agent.version_control._open_or_create_file_for_reading"
        with mock.patch(o_fn) as m_open:
            m_open.return_value = StringIO('{"3.4": "bar", "5.6": "foo"}')
            added, updated, removed = self.version_control.diff({
                VIF("1", "2"): "fu",
                VIF("5", "6"): "baz",
            })
            m_open.assert_called_once_with(self.FILEPATH)
            self.assertEqual(added, [VIF("1", "2")])
            self.assertEqual(updated, [VIF("5", "6")])
            self.assertEqual(removed, [VIF("3", "4")])

    def test_commit_without_changes(self):
        o_fn = "quark.agent.version_control._open_or_create_file_for_reading"
        with mock.patch(o_fn) as m_open:
            read_file = StringIO('{"3.4": "bar", "5.6": "foo"}')
            write_file = StringIO()
            m_open.side_effect = (read_file, write_file)
            self.version_control.commit({
                VIF("3", "4"): "bar",
                VIF("5", "6"): "foo"
            })
            m_open.assert_has_calls([mock.call(self.FILEPATH)])

    def test_commit_with_changes(self):
        with contextlib.nested(
            mock.patch("__builtin__.open"),
            mock.patch("json.dump")
        ) as (m_open, jdump):
            read_file = StringIO('{"3.4": "bar", "5.6": "foo"}')
            write_file = StringIO()
            m_open.side_effect = (read_file, write_file)
            self.version_control.commit({
                VIF("1", "2"): "fu",
                VIF("5", "6"): "baz"
            })
            jdump.assert_called_once_with(
                {"1.2": "fu", "5.6": "baz"},
                write_file)
