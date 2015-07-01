# Copyright 2013 Openstack Foundation
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

from neutron.common import exceptions
from oslo_config import cfg

from quark import network_strategy
from quark.tests import test_base


class TestJSONStrategy(test_base.TestBase):
    def setUp(self):
        self.context = None
        self.strategy = {"public_network":
                         {"required": True,
                          "bridge": "xenbr0",
                          "children": {"nova": "child_net"}}}
        strategy_json = json.dumps(self.strategy)
        cfg.CONF.set_override("default_net_strategy", strategy_json, "QUARK")

    def test_get_assignable_networks_default_strategy(self):
        json_strategy = network_strategy.JSONStrategy()
        net_ids = json_strategy.get_assignable_networks(self.context)
        self.assertEqual("public_network", net_ids[0])

    def test_get_assignable_networks_custom_strategy(self):
        custom = {"private_network": self.strategy["public_network"]}
        json_strategy = network_strategy.JSONStrategy(json.dumps(custom))
        net_ids = json_strategy.get_assignable_networks(self.context)
        self.assertEqual("private_network", net_ids[0])

    def test_get_network(self):
        json_strategy = network_strategy.JSONStrategy()
        net = json_strategy.get_network(self.context, "public_network")
        self.assertEqual(net["bridge"], "xenbr0")

    def test_split_network_ids(self):
        json_strategy = network_strategy.JSONStrategy()
        net_ids = ["foo_net", "public_network"]
        tenant, assignable = json_strategy.split_network_ids(self.context,
                                                             net_ids)
        self.assertTrue("foo_net" in tenant)
        self.assertTrue("foo_net" not in assignable)
        self.assertTrue("public_network" not in tenant)
        self.assertTrue("public_network" in assignable)

    def test_get_parent_network(self):
        json_strategy = network_strategy.JSONStrategy(None)
        parent_net = json_strategy.get_parent_network("child_net")
        self.assertEqual(parent_net, "public_network")

    def test_get_parent_network_no_parent(self):
        json_strategy = network_strategy.JSONStrategy(None)
        parent_net = json_strategy.get_parent_network("bar_network")
        self.assertEqual(parent_net, "bar_network")

    def test_best_match_network_id(self):
        json_strategy = network_strategy.JSONStrategy(None)
        net = json_strategy.best_match_network_id(self.context,
                                                  "public_network", "nova")
        self.assertEqual(net, "child_net")

    def test_best_match_network_net_not_in_strategy(self):
        json_strategy = network_strategy.JSONStrategy(None)
        net = json_strategy.best_match_network_id(self.context,
                                                  "foo_net", "nova")
        self.assertEqual(net, "foo_net")

    def test_best_match_network_no_valid_child(self):
        json_strategy = network_strategy.JSONStrategy(None)
        with self.assertRaises(exceptions.NetworkNotFound):
            json_strategy.best_match_network_id(self.context,
                                                "public_network", "derpa")
