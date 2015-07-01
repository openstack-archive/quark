# Copyright (c) 2015 OpenStack Foundation
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

import contextlib

from oslo_config import cfg

from quark import environment as env
from quark.tests import test_base


class TestEnvironment(test_base.TestBase):
    def setUp(self):
        super(TestEnvironment, self).setUp()
        self.MAGIC_VALUE = "12345"

    @contextlib.contextmanager
    def _fixture(self, has_capability):
        old_override = cfg.CONF.QUARK.environment_capabilities
        if has_capability:
            override = env.Capabilities.SECURITY_GROUPS
        else:
            override = ""

        cfg.CONF.set_override("environment_capabilities",
                              override,
                              "QUARK")
        yield

        cfg.CONF.set_override("environment_capabilities",
                              old_override,
                              "QUARK")

    @env.has_capability(env.Capabilities.SECURITY_GROUPS)
    def foo(self):
        return self.MAGIC_VALUE

    def test_has_capability_True(self):
        with self._fixture(True):
            self.assertEqual(self.foo(), self.MAGIC_VALUE)

    def test_has_capability_False(self):
        with self._fixture(False):
            self.assertIsNone(self.foo())
