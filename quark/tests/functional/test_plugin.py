# Copyright (c) 2016 Rackspace Hosting Inc.
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

from neutron import context
from neutron_lib import exceptions as n_exc

from quark import plugin
from quark.tests.functional.base import BaseFunctionalTest


class QuarkPluginNegativeTest(BaseFunctionalTest):
    def setUp(self):
        super(QuarkPluginNegativeTest, self).setUp()
        self.plugin = plugin.Plugin()
        self.blank_context = context.Context(None, None, is_admin=True)

        self.with_tenant_id = {"thing": {"tenant_id": "stuff"}}
        self.without_tenant_id = {"thing": {"attr": "stuff"}}


class QuarkPluginTenantlessNegativeTests(QuarkPluginNegativeTest):

    def test_tenant_check_no_raise(self):
        ret = self.plugin._fix_missing_tenant_id(
            self.blank_context, self.with_tenant_id, "thing")
        self.assertEqual(None, ret)

    def test_tenant_check_raises_if_no_tenant(self):
        with self.assertRaises(n_exc.BadRequest):
            self.plugin._fix_missing_tenant_id(
                self.blank_context, self.without_tenant_id, "thing")

    def test_tenant_check_no_raise_if_tenant_in_context(self):
        self.plugin._fix_missing_tenant_id(
            self.context, self.without_tenant_id, "thing")

    def test_tenant_check_raises_missing_body(self):
        with self.assertRaises(n_exc.BadRequest):
            self.plugin._fix_missing_tenant_id(
                self.blank_context, {}, "thing")

        with self.assertRaises(n_exc.BadRequest):
            self.plugin._fix_missing_tenant_id(
                self.blank_context, None, "thing")
