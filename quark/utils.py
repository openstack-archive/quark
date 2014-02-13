# Copyright 2013 Openstack Foundation
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
#  under the License.

import sys

import contextlib

from neutron.api.v2 import attributes
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)


def attr_specified(param):
    return param is not attributes.ATTR_NOT_SPECIFIED


def pop_param(attrs, param, default=None):
    val = attrs.pop(param, default)
    if attr_specified(val):
        return val
    return default


class Command(object):
    def __init__(self, func):
        self.func = func
        self.result = None
        self.called = False

    def __call__(self, *args, **kwargs):
        self.called = True
        self.result = self.func(*args, **kwargs)
        return self.result


class CommandManager(object):
    def __init__(self):
        self.do_commands = []
        self.undo_commands = []
        self.results = []

    @contextlib.contextmanager
    def execute(self, exc=None):
        try:
            yield self
        except Exception:
            exc_info = sys.exc_info()
            LOG.exception("Exception in transaction", exc_info=exc_info)
            self.rollback()
            raise exc_info[1]

    def do(self, func):
        cmd = Command(func)
        self.do_commands.append(cmd)
        return cmd

    def undo(self, func):
        cmd = Command(func)
        self.undo_commands.append(cmd)
        return cmd

    def rollback(self):
        do_commands = reversed(self.do_commands)
        for cmd in reversed(self.undo_commands):
            do = do_commands.next()
            if not do.called:
                continue
            try:
                cmd(do.result)
            except Exception:
                LOG.exception("Rollback failed and wasn't caught!")
