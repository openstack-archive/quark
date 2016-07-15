# Copyright (c) 2016 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import mock
from quark.tests import test_base
from quark import utils


def func_do(**kwargs):
    if 'rollback' in kwargs and kwargs['rollback']:
        return True
    else:
        return False


def func_undo(**kwargs):
    if 'rollback' in kwargs and kwargs['rollback']:
        return True
    else:
        return False


class QuarkCommandManagerTest(test_base.TestBase):
    def setUp(self):
        super(QuarkCommandManagerTest, self).setUp()
        # Using globals here because of callbacks
        self.is_rollback_do = False
        self.is_rollback_undo = True

    @mock.patch('quark.tests.test_command_manager.func_undo')
    @mock.patch('quark.tests.test_command_manager.func_do')
    def test_command_manager_no_undo(self,
                                     func_do_notifier,
                                     func_undo_notifier):
        """Test that undo is not called when everything is good"""
        try:
            with utils.CommandManager().execute() as cmd_mgr:
                @cmd_mgr.do
                def f(**kwargs):
                    func_do(**kwargs)

                @cmd_mgr.undo
                def f_undo(*args, **kwargs):
                    func_undo(**kwargs)

                f()
        except Exception:
            pass

        self.assertTrue(func_do_notifier.called)
        self.assertFalse(func_undo_notifier.called)

    @mock.patch('quark.tests.test_command_manager.func_undo')
    def test_command_manager_undo(self, func_undo_notifier):
        """Test that undo is called when the do function raises"""
        try:
            with utils.CommandManager().execute() as cmd_mgr:
                @cmd_mgr.do
                def f(**kwargs):
                    raise Exception

                @cmd_mgr.undo
                def f_undo(*args, **kwargs):
                    func_undo(**kwargs)

                f()
        except Exception:
            pass

        self.assertTrue(func_undo_notifier.called)

    def test_rollback_is_passed_to_do(self):
        """Tests that the do function has rollback set to False"""
        self.is_rollback_do = True
        try:
            with utils.CommandManager().execute() as cmd_mgr:
                @cmd_mgr.do
                def f(**kwargs):
                    return func_do(**kwargs)

                @cmd_mgr.undo
                def f_undo(*args, **kwargs):
                    func_undo(**kwargs)

                self.is_rollback_do = f()

        except Exception:
            pass

        self.assertFalse(self.is_rollback_do)

    def test_rollback_is_passed_to_undo(self):
        """Tests that the undo function has rollback set to True"""
        self.is_rollback_undo = False
        try:
            with utils.CommandManager().execute() as cmd_mgr:
                @cmd_mgr.do
                def f(**kwargs):
                    raise Exception

                @cmd_mgr.undo
                def f_undo(*args, **kwargs):
                    self.is_rollback_undo = func_undo(**kwargs)

                f()
        except Exception:
            pass

        self.assertTrue(self.is_rollback_undo)
