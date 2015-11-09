# Copyright (c) 2013 OpenStack Foundation
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

from quark.drivers import base
from quark.tests import test_base


class TestBaseDriver(test_base.TestBase):
    def setUp(self):
        super(TestBaseDriver, self).setUp()
        self.driver = base.BaseDriver()

    def test_load_config(self):
        self.driver.load_config()

    def test_get_connection(self):
        self.driver.get_connection()

    def test_select_ipam_strategy(self):
        strategy = self.driver.select_ipam_strategy(1, "ANY")
        self.assertEqual(strategy, "ANY")

    def test_create_network(self):
        self.driver.create_network(context=self.context, network_name="public")

    def test_delete_network(self):
        self.driver.delete_network(context=self.context, network_id=1)

    def test_create_port(self):
        self.driver.create_port(context=self.context, network_id=1, port_id=2)

    def test_update_port(self):
        self.driver.update_port(context=self.context, network_id=1, port_id=2)

    def test_delete_port(self):
        self.driver.delete_port(context=self.context, port_id=2)

    def test_diag_network(self):
        diag = self.driver.diag_network(self.context, network_id=1)
        self.assertEqual(diag, {})

    def test_diag_port(self):
        diag = self.driver.diag_port(self.context, network_id=1)
        self.assertEqual(diag, {})

    def test_create_security_group(self):
        self.driver.create_security_group(context=self.context,
                                          group_name="mygroup")

    def test_delete_security_group(self):
        self.driver.delete_security_group(context=self.context,
                                          group_id=3)

    def test_update_security_group(self):
        self.driver.update_security_group(context=self.context,
                                          group_id=3)

    def test_create_security_group_rule(self):
        rule = {'ethertype': 'IPv4', 'direction': 'ingress'}
        self.driver.create_security_group_rule(context=self.context,
                                               group_id=3,
                                               rule=rule)

    def test_delete_security_group_rule(self):
        rule = {'ethertype': 'IPv4', 'direction': 'ingress'}
        self.driver.delete_security_group_rule(context=self.context,
                                               group_id=3,
                                               rule=rule)
