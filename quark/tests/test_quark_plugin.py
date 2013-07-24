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


import mock
from neutron.db import api as db_api
from oslo.config import cfg

import quark.plugin

from quark.tests import test_base


class TestQuarkPlugin(test_base.TestBase):
    def setUp(self):
        super(TestQuarkPlugin, self).setUp()

        cfg.CONF.set_override('quota_ports_per_network', 1, 'QUOTAS')
        cfg.CONF.set_override('connection', 'sqlite://', 'database')
        db_api.configure_db()
        self.plugin = quark.plugin.Plugin()

    def tearDown(self):
        db_api.clear_db()


class TestQuarkAPIExtensions(TestQuarkPlugin):
    """Adds coverage for appending the API extension path."""
    def test_append_quark_extensions(self):
        conf = mock.MagicMock()
        conf.__contains__.return_value = False
        quark.plugin.append_quark_extensions(conf)
        self.assertEqual(conf.set_override.call_count, 0)

    def test_append_no_extension_path(self):
        conf = mock.MagicMock()
        conf.__contains__.return_value = True
        with mock.patch("quark.plugin.extensions") as extensions:
            extensions.__path__ = ["apple", "banana", "carrot"]
            quark.plugin.append_quark_extensions(conf)
            conf.__contains__.assert_called_once_with("api_extensions_path")
            conf.set_override.assert_called_once_with(
                "api_extensions_path",
                "apple:banana:carrot")
