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

import contextlib
import json

import mock
from neutron.common import exceptions
from neutron import context
from oslo.config import cfg

from quark.db import api as db_api
from quark.db import models
from quark import exceptions as q_exc
from quark import network_strategy
from quark import plugin_views
from quark.tests import test_quark_plugin


class TestQuarkGetNetworks(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, nets=None, subnets=None):
        net_mods = []
        subnet_mods = []

        for subnet in subnets:
            subnet_mod = models.Subnet()
            subnet_mod.update(subnet)
            subnet_mods.append(subnet_mod)

        if isinstance(nets, list):
            for net in nets:
                net_mod = models.Network()
                net_mod.update(net)
                net_mod["subnets"] = subnet_mods
                net_mods.append(net_mod)
        else:
            if nets:
                net_mods = nets.copy()
                net_mods["subnets"] = subnet_mods
            else:
                net_mods = nets

        db_mod = "quark.db.api"
        with mock.patch("%s.network_find" % db_mod) as net_find:
            net_find.return_value = net_mods
            yield

    def test_get_networks(self):
        subnet = dict(id=1)
        net = dict(id=1, tenant_id=self.context.tenant_id, name="public",
                   status="ACTIVE")
        with self._stubs(nets=[net], subnets=[subnet]):
            nets = self.plugin.get_networks(self.context, {})
            for key in net.keys():
                self.assertEqual(nets[0][key], net[key])
            self.assertEqual(nets[0]["subnets"][0], 1)

    def test_get_network(self):
        subnet = dict(id=1)
        net = dict(id=1, tenant_id=self.context.tenant_id, name="public",
                   status="ACTIVE")
        expected = net.copy()
        expected["admin_state_up"] = None
        expected["shared"] = False
        expected["status"] = "ACTIVE"
        with self._stubs(nets=net, subnets=[subnet]):
            res = self.plugin.get_network(self.context, 1)
            for key in expected.keys():
                self.assertEqual(res[key], expected[key])
            self.assertEqual(res["subnets"][0], 1)

    def test_get_network_no_network_fails(self):
        with self._stubs(nets=None, subnets=[]):
            with self.assertRaises(exceptions.NetworkNotFound):
                self.plugin.get_network(self.context, 1)


class TestQuarkGetNetworksShared(test_quark_plugin.TestQuarkPlugin):
    def setUp(self):
        super(TestQuarkGetNetworksShared, self).setUp()
        self.strategy = {"public_network":
                         {"required": True,
                          "bridge": "xenbr0",
                          "children": {"nova": "child_net"}}}
        self.strategy_json = json.dumps(self.strategy)
        self.old = plugin_views.STRATEGY
        plugin_views.STRATEGY = network_strategy.JSONStrategy(
            self.strategy_json)
        cfg.CONF.set_override("default_net_strategy", self.strategy_json,
                              "QUARK")

    def tearDown(self):
        plugin_views.STRATEGY = self.old

    @contextlib.contextmanager
    def _stubs(self, nets=None, subnets=None):
        net_mods = []

        if isinstance(nets, list):
            for net in nets:
                subnet_mods = []
                subnets = net.pop('subnets', [])

                for subnet in subnets:
                    subnet_mod = models.Subnet()
                    subnet_mod.update(subnet)
                    subnet_mods.append(subnet_mod)

                net_mod = models.Network()
                net_mod.update(net)
                net_mod["subnets"] = subnet_mods
                net_mods.append(net_mod)
        else:
            if nets:
                net_mods = nets.copy()
            else:
                net_mods = nets

        db_mod = "quark.db.api"

        db_api.STRATEGY = network_strategy.JSONStrategy(self.strategy_json)
        network_strategy.STRATEGY = network_strategy.JSONStrategy(
            self.strategy_json)

        with mock.patch("%s._network_find" % db_mod) as net_find:
            net_find.return_value = net_mods
            yield net_find

    def test_get_networks_shared(self):
        net0 = dict(id='public_network', tenant_id=self.context.tenant_id,
                    name="mynet", status="ACTIVE", subnets=[dict(id=0)])
        net1 = dict(id=1, tenant_id=self.context.tenant_id, name="mynet",
                    status="ACTIVE", subnets=[dict(id=1)])
        with self._stubs(nets=[net0, net1]) as net_find:
            ret = self.plugin.get_networks(self.context, {"shared": [True]})
            """ Includes regression for RM8483. """
            for net in ret:
                if net['shared']:
                    self.assertEqual(0, len(net['subnets']))
                else:
                    self.assertEqual(1, len(net['subnets']))
            net_find.assert_called_with(self.context, None,
                                        join_subnets=True,
                                        defaults=["public_network"])

    def test_get_networks_shared_false(self):
        net0 = dict(id='public_network', tenant_id=self.context.tenant_id,
                    name="mynet", status="ACTIVE", subnets=[dict(id=0)])
        net1 = dict(id=1, tenant_id=self.context.tenant_id, name="mynet",
                    status="ACTIVE")
        with self._stubs(nets=[net0, net1]) as net_find:
            invert = db_api.INVERT_DEFAULTS
            self.plugin.get_networks(self.context, {"shared": [False]})
            net_find.assert_called_with(self.context, None, join_subnets=True,
                                        defaults=[invert, "public_network"])

    def test_get_networks_no_shared(self):
        net0 = dict(id='public_network', tenant_id=self.context.tenant_id,
                    name="mynet", status="ACTIVE", subnets=[dict(id=0)])
        net1 = dict(id=1, tenant_id=self.context.tenant_id, name="mynet",
                    status="ACTIVE")
        with self._stubs(nets=[net0, net1]) as net_find:
            self.plugin.get_networks(self.context, {})
            net_find.assert_called_with(self.context, None, join_subnets=True,
                                        defaults=[])


class TestQuarkGetNetworkCount(test_quark_plugin.TestQuarkPlugin):
    def test_get_port_count(self):
        """This isn't really testable."""
        with mock.patch("quark.db.api.network_count_all"):
            self.plugin.get_networks_count(self.context, {})


class TestQuarkUpdateNetwork(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, net=None):
        net_mod = net
        if net:
            net_mod = net.copy()

        db_mod = "quark.db.api"
        with contextlib.nested(
            mock.patch("%s.network_find" % db_mod),
            mock.patch("%s.network_update" % db_mod)
        ) as (net_find, net_update):
            net_find.return_value = net_mod
            net_update.return_value = net_mod
            yield net_update

    def test_update_network(self):
        net = dict(id=1)
        new_net = net.copy()
        new_net["ipam_strategy"] = "BOTH_REQUIRED"
        with self._stubs(net=net) as net_update:
            self.plugin.update_network(self.context, 1, dict(network=new_net))
            net_update.assert_called_once_with(
                self.context, net, id=net["id"])

    def test_update_network_not_found_fails(self):
        with self._stubs(net=None):
            with self.assertRaises(exceptions.NetworkNotFound):
                self.plugin.update_network(self.context, 1, None)

    def test_update_network_admin_set_ipam_strategy(self):
        net = dict(id=1)
        new_net = net.copy()
        new_net["ipam_strategy"] = "BOTH_REQUIRED"

        admin_ctx = self.context.elevated()
        with self._stubs(net=net) as net_update:
            self.plugin.update_network(admin_ctx, 1, dict(network=new_net))
            net_update.assert_called_once_with(
                admin_ctx, net, ipam_strategy=new_net["ipam_strategy"],
                id=net["id"])


class TestQuarkDeleteNetwork(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, net=None, ports=None, subnets=None):
        subnets = subnets or []
        net_mod = net
        port_mods = []
        subnet_mods = []

        for port in ports:
            port_model = models.Port()
            port_model.update(port)
            port_mods.append(port_model)

        for subnet in subnets:
            subnet_mod = models.Subnet()
            subnet_mod.update(subnet)
            subnet_mods.append(subnet_mod)

        if net:
            net_mod = models.Network()
            net_mod.update(net)
            net_mod.ports = port_mods
            net_mod["subnets"] = subnet_mods
            net_mod["network_plugin"] = "BASE"

        db_mod = "quark.db.api"
        with contextlib.nested(
            mock.patch("%s.network_find" % db_mod),
            mock.patch("%s.network_delete" % db_mod),
            mock.patch("quark.drivers.base.BaseDriver.delete_network"),
            mock.patch("%s.subnet_delete" % db_mod)
        ) as (net_find, net_delete, driver_net_delete, subnet_del):
            net_find.return_value = net_mod
            yield net_delete

    def test_delete_network(self):
        net = dict(id=1)
        with self._stubs(net=net, ports=[]) as net_delete:
            self.plugin.delete_network(self.context, 1)
            self.assertTrue(net_delete.called)

    def test_delete_network_with_ports_fails(self):
        net = dict(id=1)
        port = dict(id=2)
        with self._stubs(net=net, ports=[port]):
            with self.assertRaises(exceptions.NetworkInUse):
                self.plugin.delete_network(self.context, 1)

    def test_delete_network_not_found_fails(self):
        with self._stubs(net=None, ports=[]):
            with self.assertRaises(exceptions.NetworkNotFound):
                self.plugin.delete_network(self.context, 1)

    def test_delete_network_with_subnets_passes(self):
        net = dict(id=1)
        subnet = dict(id=1)
        with self._stubs(net=net, ports=[], subnets=[subnet]) as net_delete:
            self.plugin.delete_network(self.context, 1)
            self.assertTrue(net_delete.called)


class TestQuarkCreateNetwork(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, net=None, subnet=None, ports=None, find_net=False):
        net_mod = net
        subnet_mod = None
        if net:
            net_mod = models.Network()
            net_mod.update(net)

        if subnet:
            subnet_mod = models.Subnet()
            subnet_mod.update(subnet)

        found_net = None
        if find_net:
            found_net = models.Network()

        db_mod = "quark.db.api"
        with contextlib.nested(
            mock.patch("%s.network_create" % db_mod),
            mock.patch("%s.subnet_create" % db_mod),
            mock.patch("quark.drivers.base.BaseDriver.create_network"),
            mock.patch("%s.network_find" % db_mod)
        ) as (net_create, sub_create, driver_net_create, net_find):
            net_create.return_value = net_mod
            sub_create.return_value = subnet_mod
            net_find.return_value = found_net
            yield net_create

    def test_create_network(self):
        net = dict(id=1, name="public", admin_state_up=True,
                   tenant_id=0, network_plugin="BASE")
        with self._stubs(net=net) as net_create:
            net = self.plugin.create_network(self.context, dict(network=net))
            self.assertTrue(net_create.called)
            self.assertEqual(len(net.keys()), 7)
            self.assertIsNotNone(net["id"])
            self.assertEqual(net["name"], "public")
            self.assertIsNone(net["admin_state_up"])
            self.assertEqual(net["status"], "ACTIVE")
            self.assertEqual(net["subnets"], [])
            self.assertEqual(net["shared"], False)
            self.assertEqual(net["tenant_id"], 0)

    def test_create_network_with_subnets(self):
        subnet = dict(id=2, cidr="172.168.0.0/24", tenant_id=0)
        net = dict(id=1, name="public", admin_state_up=True,
                   tenant_id=0)
        with self._stubs(net=net, subnet=subnet) as net_create:
            net.update(dict(subnets=[dict(subnet=subnet)]))
            net = self.plugin.create_network(self.context, dict(network=net))
            self.assertTrue(net_create.called)
            self.assertEqual(len(net.keys()), 7)
            self.assertIsNotNone(net["id"])
            self.assertEqual(net["name"], "public")
            self.assertIsNone(net["admin_state_up"])
            self.assertEqual(net["status"], "ACTIVE")
            self.assertEqual(net["subnets"], [2])
            self.assertEqual(net["shared"], False)
            self.assertEqual(net["tenant_id"], 0)

    def test_create_network_with_id(self):
        net = dict(id="abcdef", name="public", admin_state_up=True,
                   tenant_id=0)
        ctxt = context.Context('fake', 'fake', is_admin=True,
                               load_admin_roles=False)
        with self._stubs(net=net):
            res = self.plugin.create_network(ctxt, dict(network=net))
            self.assertEqual(net["id"], res["id"])

    def test_create_network_with_id_already_exists_raises(self):
        net = dict(id="abcdef", name="public", admin_state_up=True,
                   tenant_id=0)
        ctxt = context.Context('fake', 'fake', is_admin=True,
                               load_admin_roles=False)
        with self._stubs(net=net, find_net=True):
            with self.assertRaises(q_exc.NetworkAlreadyExists):
                self.plugin.create_network(ctxt, dict(network=net))

    def test_create_network_with_id_not_admin_ignores_id(self):
        net = dict(id="abcdef", name="public", admin_state_up=True,
                   tenant_id=0)
        with self._stubs(net=net):
            res = self.plugin.create_network(self.context, dict(network=net))
            self.assertNotEqual(net["id"], res["id"])

    def test_create_network_with_ipam_strategy(self):
        net = dict(id="abcdef", name="public", admin_state_up=True,
                   tenant_id=0, ipam_strategy="BOTH")
        admin_context = self.context.elevated()
        original = cfg.CONF.QUARK.show_ipam_strategy

        cfg.CONF.set_override('show_ipam_strategy', True, "QUARK")
        with self._stubs(net=net):
            res = self.plugin.create_network(admin_context, dict(network=net))
            self.assertEqual(res["ipam_strategy"], net["ipam_strategy"])
        cfg.CONF.set_override('show_ipam_strategy', original, "QUARK")

    def test_create_network_with_bad_ipam_strategy_raises(self):
        net = dict(id="abcdef", name="public", admin_state_up=True,
                   tenant_id=0, ipam_strategy="BUSTED")
        admin_context = self.context.elevated()
        with self._stubs(net=net):
            with self.assertRaises(q_exc.InvalidIpamStrategy):
                self.plugin.create_network(admin_context, dict(network=net))


class TestQuarkDiagnoseNetworks(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, nets=None, subnets=None):
        net_mods = []
        subnet_mods = []

        if subnets:
            for subnet in subnets:
                subnet_mod = models.Subnet()
                subnet_mod.update(subnet)
                subnet_mods.append(subnet_mod)

        if nets:
            for net in nets:
                net_mod = models.Network()
                net_mod["network_plugin"] = "BASE"
                net_mod.update(net)
                net_mod["subnets"] = subnet_mods
                net_mods.append(net_mod)
        else:
            if nets:
                net_mods = nets.copy()
                net_mods["subnets"] = subnet_mods
            else:
                net_mods = nets

        db_mod = "quark.db.api"
        with mock.patch("%s.network_find" % db_mod) as net_find:
            net_find.return_value = net_mods
            yield

    def test_diagnose_network_no_network_found(self):
        with self._stubs():
            with self.assertRaises(exceptions.NetworkNotFound):
                self.plugin.diagnose_network(self.context.elevated(), "12345",
                                             None)

    def test_diagnose_network_not_authorized(self):
        with self._stubs():
            with self.assertRaises(exceptions.NotAuthorized):
                self.plugin.diagnose_network(self.context, "12345",
                                             None)

    def test_diagnose_network_with_wildcard_and_no_networks(self):
        db_mod = "quark.db.api"
        with mock.patch("%s.network_find" % db_mod) as net_find:
            net_find.return_value = []
            actual = self.plugin.diagnose_network(self.context.elevated(),
                                                  "*", {})
            expected = {'networks': []}
            self.assertEqual(expected, actual)

    def test_diagnose_network_with_wildcard_and_networks(self):
        subnet = dict(id=1)
        net = dict(id=1, tenant_id=self.context.tenant_id, name="public",
                   status="ACTIVE", network_plugin="BASE")
        with self._stubs(nets=[net], subnets=[subnet]):
            db_mod = "quark.db.api"
            with mock.patch("%s.network_find" % db_mod) as net_find:
                net_find.return_value = [net]
                nets = self.plugin.diagnose_network(self.context.elevated(),
                                                    "*", {})
                net.pop("network_plugin")
                for key in net.keys():
                    self.assertEqual(nets['networks'][0][key], net[key])
