# Copyright 2013 Rackspace Hosting Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import json

from oslo_config import cfg

from quark import network_strategy
from quark.tests import test_base


class TestJSONStrategy(test_base.TestBase):
    def setUp(self):
        self.strategy = {"public_network": {"bridge": "xenbr0",
                                            "subnets": {"4": "public_v4",
                                                        "6": "public_v6"}}}
        strategy_json = json.dumps(self.strategy)
        cfg.CONF.set_override("default_net_strategy", strategy_json, "QUARK")

    def test_get_network(self):
        json_strategy = network_strategy.JSONStrategy()
        net = json_strategy.get_network("public_network")
        self.assertEqual(net["bridge"], "xenbr0")

    def test_split_network_ids(self):
        json_strategy = network_strategy.JSONStrategy()
        net_ids = ["foo_net", "public_network"]
        tenant, assignable = json_strategy.split_network_ids(net_ids)
        self.assertTrue("foo_net" in tenant)
        self.assertTrue("foo_net" not in assignable)
        self.assertTrue("public_network" not in tenant)
        self.assertTrue("public_network" in assignable)

    def test_split_subnet_ids(self):
        json_strategy = network_strategy.JSONStrategy()
        subnet_ids = ["tenant_subnet", "public_v6"]
        tenant, assignable = json_strategy.split_subnet_ids(subnet_ids)
        self.assertTrue("tenant_subnet" in tenant)
        self.assertTrue("tenant_subnet" not in assignable)
        self.assertTrue("public_v6" not in tenant)
        self.assertTrue("public_v6" in assignable)

    def test_is_provider_network(self):
        json_strategy = network_strategy.JSONStrategy()
        self.assertTrue(json_strategy.is_provider_network("public_network"))

    def test_is_not_provider_network(self):
        json_strategy = network_strategy.JSONStrategy()
        self.assertFalse(json_strategy.is_provider_network("tenant_network"))

    def test_is_provider_subnet(self):
        json_strategy = network_strategy.JSONStrategy()
        self.assertTrue(json_strategy.is_provider_subnet("public_v4"))

    def test_is_not_provider_subnet(self):
        json_strategy = network_strategy.JSONStrategy()
        self.assertFalse(json_strategy.is_provider_network("tenant_v4"))

    def test_get_provider_networks(self):
        json_strategy = network_strategy.JSONStrategy()
        expected = "public_network"
        nets = json_strategy.get_provider_networks()
        self.assertTrue(expected in nets)
        self.assertEqual(1, len(nets))

    def test_get_provider_subnets(self):
        json_strategy = network_strategy.JSONStrategy()
        expected = ["public_v4", "public_v6"]
        subs = json_strategy.get_provider_subnets()
        for sub in expected:
            self.assertTrue(sub in subs)
        self.assertEqual(2, len(subs))

    def test_get_network_for_subnet(self):
        json_strategy = network_strategy.JSONStrategy()
        net = json_strategy.get_network_for_subnet("public_v4")
        self.assertEqual("public_network", net)

    def test_get_network_for_subnet_matches_none(self):
        json_strategy = network_strategy.JSONStrategy()
        net = json_strategy.get_network_for_subnet("tenant_v4")
        self.assertIsNone(net)

    def test_subnet_ids_for_network(self):
        json_strategy = network_strategy.JSONStrategy()
        expected = ["public_v4", "public_v6"]
        subs = json_strategy.subnet_ids_for_network("public_network")
        for sub in expected:
            self.assertTrue(sub in subs)
        self.assertEqual(2, len(subs))

    def test_subnet_ids_for_network_matches_none(self):
        json_strategy = network_strategy.JSONStrategy()
        subs = json_strategy.subnet_ids_for_network("tenant_network")
        self.assertIsNone(subs)

    def test_get_provider_subnet_id(self):
        json_strategy = network_strategy.JSONStrategy()
        net_id = "public_network"
        ip_version = 4
        sub = json_strategy.get_provider_subnet_id(net_id, ip_version)
        self.assertEqual(sub, "public_v4")

    def test_get_provider_subnet_id_matches_none(self):
        json_strategy = network_strategy.JSONStrategy()
        net_id = "tenant_network"
        ip_version = 4
        sub = json_strategy.get_provider_subnet_id(net_id, ip_version)
        self.assertIsNone(sub)
