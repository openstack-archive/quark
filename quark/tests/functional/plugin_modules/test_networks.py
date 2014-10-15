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
# License for# the specific language governing permissions and limitations
#  under the License.

import contextlib
import json

import mock
import netaddr
from neutron.common import exceptions
from neutron.common import rpc
from oslo.config import cfg

from quark.db import api as db_api
import quark.ipam
from quark import network_strategy
import quark.plugin
import quark.plugin_modules.mac_address_ranges as macrng_api
import quark.plugin_modules.subnets as subnet_api
from quark.tests.functional.base import BaseFunctionalTest


class QuarkNetworkFunctionalTest(BaseFunctionalTest):
    def setUp(self):
        super(QuarkNetworkFunctionalTest, self).setUp()

        patcher = mock.patch("neutron.common.rpc.messaging")
        patcher.start()
        self.addCleanup(patcher.stop)
        rpc.init(mock.MagicMock())


class QuarkGetNetwork(QuarkNetworkFunctionalTest):

    def test_show_ipam_strategy(self):
        plugin = quark.plugin.Plugin()
        network = dict(name="public", tenant_id="fake", network_plugin="BASE")
        network = dict(network=network)
        original = cfg.CONF.QUARK.show_ipam_strategy

        cfg.CONF.set_override('show_ipam_strategy', True, "QUARK")
        net = plugin.create_network(self.context, network)
        self.assertTrue('ipam_strategy' in net)
        net = plugin.get_network(self.context, net['id'])
        self.assertTrue('ipam_strategy' in net)

        cfg.CONF.set_override('show_ipam_strategy', False, "QUARK")
        net = plugin.create_network(self.context, network)
        self.assertFalse('ipam_strategy' in net)
        net = plugin.get_network(self.context, net['id'])
        self.assertFalse('ipam_strategy' in net)

        cfg.CONF.set_override('show_ipam_strategy', original, "QUARK")


class QuarkDeleteNetworKDeallocatedIPs(QuarkNetworkFunctionalTest):
    @contextlib.contextmanager
    def _stubs(self, network, subnet, dealloc=True):
        self.plugin = quark.plugin.Plugin()
        self.ipam = quark.ipam.QuarkIpamANY()
        with self.context.session.begin():
            net_mod = db_api.network_create(self.context, **network)
            subnet["network"] = net_mod
            next_auto = subnet.pop("next_auto_assign_ip", 0)
            sub_mod = db_api.subnet_create(self.context, **subnet)
            db_api.subnet_update(self.context,
                                 sub_mod,
                                 next_auto_assign_ip=next_auto)

        ip_addr = []
        self.ipam.allocate_ip_address(self.context, ip_addr,
                                      net_mod["id"], 0, 0)
        if dealloc:
            self.ipam.deallocate_ip_address(self.context, ip_addr[0])
        yield net_mod

    def test_delete_network_with_allocated_ips_fails(self):
        ipnet = netaddr.IPNetwork("0.0.0.0/24")
        next_ip = ipnet.ipv6().first + 2

        network = dict(name="public", tenant_id="fake", network_plugin="BASE")
        subnet = dict(id=1, ip_version=4, next_auto_assign_ip=next_ip,
                      cidr="0.0.0.0/24",
                      ip_policy=None, tenant_id="fake")
        with self._stubs(network, subnet, dealloc=False) as net_mod:
            with self.assertRaises(exceptions.SubnetInUse):
                self.plugin.delete_network(self.context, net_mod["id"])

    def test_delete_network_with_deallocated_ips(self):
        network = dict(name="public", tenant_id="fake", network_plugin="BASE")
        ipnet = netaddr.IPNetwork("0.0.0.0/24")
        next_ip = ipnet.ipv6().first + 2
        subnet = dict(id=1, ip_version=4, next_auto_assign_ip=next_ip,
                      cidr="0.0.0.0/24",
                      ip_policy=None, tenant_id="fake")
        with self._stubs(network, subnet) as net_mod:
            try:
                self.plugin.delete_network(self.context, net_mod["id"])
            except Exception:
                self.fail("delete network raised")


class QuarkNetworkFunctionalTestRM9709(QuarkNetworkFunctionalTest):
    PUBLICNET = "00000000-0000-0000-0000-000000000000"
    SERVICENET = "11111111-1111-1111-1111-111111111111"
    TENANT_NET = "tenant-id-net"
    OTHER_NET = "other-tenant-id-net"

    def setUp(self):
        super(QuarkNetworkFunctionalTest, self).setUp()
        strategy = {self.PUBLICNET: {"bridge": "publicnet"},
                    self.SERVICENET: {"bridge": "servicenet"}}
        strategy_json = json.dumps(strategy)
        db_api.STRATEGY = network_strategy.JSONStrategy(strategy_json)
        self.plugin = quark.plugin.Plugin()

    @contextlib.contextmanager
    def _stubs(self):
        with contextlib.nested(
            mock.patch("neutron.common.rpc.get_notifier"),
            mock.patch("neutron.quota.QUOTAS.limit_check")
        ):
            mac = {'mac_address_range': dict(cidr="AA:BB:CC")}
            self.context.is_admin = True
            macrng_api.create_mac_address_range(self.context, mac)
            self.context.is_admin = False

            def _make_subnet(cidr, net_id, tenant_id):
                old_tid = self.context.tenant_id
                self.context.tenant_id = tenant_id
                network = dict(
                    id=net_id,
                    name="irrelevant",
                    tenant_id=tenant_id,
                    network_plugin="BASE",
                    ipam_strategy="ANY")
                db_api.network_create(self.context, **network)

                ip_network = netaddr.IPNetwork(cidr)
                subnet = dict(ip_version=4,
                              next_auto_assign_ip=ip_network.first,
                              cidr=cidr,
                              first_ip=ip_network.first,
                              last_ip=ip_network.last, ip_policy=None,
                              tenant_id=tenant_id)
                subnet['network_id'] = net_id
                subnet_info = {"subnet": subnet}
                subnet_api.create_subnet(self.context, subnet_info)
                self.context.tenant_id = old_tid
            _make_subnet("192.168.0.0/24", self.PUBLICNET, "rackspace")
            _make_subnet("192.168.1.0/24", self.SERVICENET, "rackspace")
            _make_subnet("192.168.2.0/24", self.TENANT_NET,
                         self.context.tenant_id)
            _make_subnet("192.168.3.0/24", self.OTHER_NET, "other-tenant")
            yield

    def test_delete_publicnet(self):
        with self._stubs():
            with self.assertRaises(exceptions.NotAuthorized):
                self.plugin.delete_network(self.context, id=self.PUBLICNET)

    def test_delete_servicenet(self):
        with self._stubs():
            with self.assertRaises(exceptions.NotAuthorized):
                self.plugin.delete_network(self.context, self.SERVICENET)

    def test_delete_tenant_net(self):
        with self._stubs():
            self.plugin.delete_network(self.context, self.TENANT_NET)

    def test_delete_other_tenant_net(self):
        with self._stubs():
            with self.assertRaises(exceptions.NetworkNotFound):
                self.plugin.delete_network(self.context, self.OTHER_NET)

    def test_delete_networks_tenant_id_none_admin(self):
        with self._stubs():
            old_tid = self.admin_context.tenant_id
            self.admin_context.tenant_id = None

            self.plugin.delete_network(self.admin_context, id=self.PUBLICNET)
            self.plugin.delete_network(self.admin_context, id=self.SERVICENET)
            self.plugin.delete_network(self.admin_context, id=self.TENANT_NET)
            self.plugin.delete_network(self.admin_context, id=self.OTHER_NET)

            self.admin_context.tenant_id = old_tid

    def test_delete_networks_tenant_id_none_not_admin(self):
        with self._stubs():
            old_tid, self.context.tenant_id = self.context.tenant_id, None

            with self.assertRaises(exceptions.NotAuthorized):
                self.plugin.delete_network(self.context, id=self.PUBLICNET)
            with self.assertRaises(exceptions.NotAuthorized):
                self.plugin.delete_network(self.context, id=self.SERVICENET)
            with self.assertRaises(exceptions.NetworkNotFound):
                self.plugin.delete_network(self.context, id=self.TENANT_NET)
            with self.assertRaises(exceptions.NetworkNotFound):
                self.plugin.delete_network(self.context, id=self.OTHER_NET)

            self.context.tenant_id = old_tid

    def test_update_publicnet(self):
        payload = dict(network=dict(name="foo"))
        with self._stubs():
            with self.assertRaises(exceptions.NotAuthorized):
                self.plugin.update_network(
                    self.context, self.PUBLICNET, payload)

    def test_update_servicenet(self):
        payload = dict(network=dict(name="foo"))
        with self._stubs():
            with self.assertRaises(exceptions.NotAuthorized):
                self.plugin.update_network(
                    self.context, self.SERVICENET, payload)

    def test_update_tenant_net(self):
        payload = dict(network=dict(name="foo"))
        with self._stubs():
            self.plugin.update_network(
                self.context, self.TENANT_NET, payload)

    def test_update_other_tenant_net(self):
        payload = dict(network=dict(name="foo"))
        with self._stubs():
            with self.assertRaises(exceptions.NetworkNotFound):
                self.plugin.update_network(
                    self.context, self.OTHER_NET, payload)

    def test_update_networks_tenant_id_none_admin(self):
        payload = dict(network=dict(name="foo"))
        with self._stubs():
            old_tid = self.admin_context.tenant_id
            self.admin_context.tenant_id = None

            self.plugin.update_network(
                self.admin_context, self.TENANT_NET, payload)
            self.plugin.update_network(
                self.admin_context, self.PUBLICNET, payload)
            self.plugin.update_network(
                self.admin_context, self.SERVICENET, payload)
            self.plugin.update_network(
                self.admin_context, self.OTHER_NET, payload)

            self.admin_context.tenant_id = old_tid

    def test_update_networks_tenant_id_none_not_admin(self):
        payload = dict(network=dict(name="foo"))
        with self._stubs():
            old_tid, self.context.tenant_id = self.context.tenant_id, None

            with self.assertRaises(exceptions.NotAuthorized):
                self.plugin.update_network(self.context,
                                           self.PUBLICNET, payload)
            with self.assertRaises(exceptions.NotAuthorized):
                self.plugin.update_network(self.context,
                                           self.SERVICENET, payload)
            with self.assertRaises(exceptions.NetworkNotFound):
                self.plugin.update_network(self.context,
                                           self.TENANT_NET, payload)
            with self.assertRaises(exceptions.NetworkNotFound):
                self.plugin.update_network(self.context,
                                           self.OTHER_NET, payload)

            self.context.tenant_id = old_tid

    def test_get_networks(self):
        with self._stubs():
            nets = self.plugin.get_networks(self.context)
            self.assertEqual(len(nets), 3)
            self.assertEqual(
                set([net["id"] for net in nets]),
                set([self.TENANT_NET, self.PUBLICNET, self.SERVICENET]))

    def test_get_networks_tenant_id_none_admin(self):
        with self._stubs():
            old_tid = self.admin_context.tenant_id
            self.admin_context.tenant_id = None
            nets = self.plugin.get_networks(self.admin_context)

            self.assertEqual(len(nets), 4)
            self.assertEqual(
                set([net["id"] for net in nets]),
                set([self.TENANT_NET, self.PUBLICNET, self.SERVICENET,
                     self.OTHER_NET]))
            self.admin_context.tenant_id = old_tid

    def test_get_networks_tenant_id_none_not_admin(self):
        with self._stubs():
            old_tid, self.context.tenant_id = self.context.tenant_id, None
            nets = self.plugin.get_networks(self.context)

            self.assertEqual(len(nets), 2)
            self.assertEqual(
                set([net["id"] for net in nets]),
                set([self.PUBLICNET, self.SERVICENET]))
            self.context.tenant_id = old_tid
