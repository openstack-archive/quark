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

import mock
import netaddr
from neutron.common import exceptions as neutron_exc

import contextlib
import json

from quark.db import api as db_api
from quark import exceptions
import quark.ipam
from quark import network_strategy
import quark.plugin
import quark.plugin_modules.mac_address_ranges as macrng_api
import quark.plugin_modules.networks as network_api
import quark.plugin_modules.ports as port_api
import quark.plugin_modules.subnets as subnet_api
from quark.tests.functional.base import BaseFunctionalTest


class QuarkFindPortsSorted(BaseFunctionalTest):
    def test_ports_sorted_by_created_at(self):
        # create a network
        network = dict(name="public", tenant_id="fake", network_plugin="BASE")
        net_mod = db_api.network_create(self.context, **network)
        # create ports
        port1 = dict(network_id=net_mod["id"], backend_key="1", device_id="1")
        port2 = dict(network_id=net_mod["id"], backend_key="1", device_id="1")
        port3 = dict(network_id=net_mod["id"], backend_key="1", device_id="1")
        port_mod1 = db_api.port_create(self.context, **port1)
        port_mod2 = db_api.port_create(self.context, **port2)
        port_mod3 = db_api.port_create(self.context, **port3)
        res = db_api.port_find(self.context, scope=db_api.ALL)
        self.assertTrue(res[0]["created_at"] < res[1]["created_at"] <
                        res[2]['created_at'])
        db_api.network_delete(self.context, net_mod)
        db_api.port_delete(self.context, port_mod1)
        db_api.port_delete(self.context, port_mod2)
        db_api.port_delete(self.context, port_mod3)


class QuarkUpdatePorts(BaseFunctionalTest):
    @contextlib.contextmanager
    def _stubs(self, network_info, subnet_info, port_info):
        self.ipam = quark.ipam.QuarkIpamANY()
        with contextlib.nested(
                mock.patch("neutron.common.rpc.get_notifier"),
                mock.patch("neutron.quota.QUOTAS.limit_check")):
            net = network_api.create_network(self.context, network_info)
            mac = {'mac_address_range': dict(cidr="AA:BB:CC")}
            self.context.is_admin = True
            macrng_api.create_mac_address_range(self.context, mac)
            self.context.is_admin = False
            subnet_info['subnet']['network_id'] = net['id']
            port_info['port']['network_id'] = net['id']
            sub = subnet_api.create_subnet(self.context, subnet_info)
            port = port_api.create_port(self.context, port_info)
            yield net, sub, port

    def test_update_fixed_ips_regression_RM9097(self):
        cidr = "192.168.1.0/24"
        ip_network = netaddr.IPNetwork(cidr)
        network = dict(name="public", tenant_id="fake", network_plugin="BASE")
        network = {"network": network}
        subnet = dict(id=1, ip_version=4, next_auto_assign_ip=2,
                      cidr=cidr, first_ip=ip_network.first,
                      last_ip=ip_network.last, ip_policy=None,
                      tenant_id="fake")
        subnet = {"subnet": subnet}
        port = {"port": dict()}

        def _make_body(ip):
            fix_ip = dict(ip_address=ip, subnet_id=sub['id'])
            port_info = {"port": dict(fixed_ips=[fix_ip])}
            return port_info

        with self._stubs(network, subnet, port) as (net, sub, port):
            id = port['id']

            ip = "192.168.1.50"
            port = port_api.update_port(self.context, id, _make_body(ip))
            self.assertEqual(ip, port['fixed_ips'][0]['ip_address'])

            with self.assertRaises(exceptions.IPAddressNotInSubnet):
                ip = "192.168.2.50"
                port = port_api.update_port(self.context, id, _make_body(ip))
                self.assertEqual(ip, port['fixed_ips'][0]['ip_address'])

            ip = "192.168.1.75"
            port = port_api.update_port(self.context, id, _make_body(ip))
            self.assertEqual(ip, port['fixed_ips'][0]['ip_address'])

            ip = "192.168.1.50"
            port = port_api.update_port(self.context, id, _make_body(ip))
            self.assertEqual(ip, port['fixed_ips'][0]['ip_address'])


class QuarkFindPortsFilterByDeviceOwner(BaseFunctionalTest):
    def test_port_list_device_owner_found_returns_only_those(self):
        # create a network
        network = dict(name="public", tenant_id="fake", network_plugin="BASE")
        net_mod = db_api.network_create(self.context, **network)
        # create ports
        port1 = dict(network_id=net_mod["id"], backend_key="1", device_id="1",
                     device_owner="Doge")
        port2 = dict(network_id=net_mod["id"], backend_key="1", device_id="1",
                     device_owner=port1["device_owner"])
        port3 = dict(network_id=net_mod["id"], backend_key="1", device_id="1",
                     device_owner="network:dhcp")
        port_mod1 = db_api.port_create(self.context, **port1)
        port_mod2 = db_api.port_create(self.context, **port2)
        port_mod3 = db_api.port_create(self.context, **port3)
        res = db_api.port_find(self.context, scope=db_api.ALL,
                               device_owner=port3["device_owner"])
        self.assertTrue(len(res) == 1)
        self.assertTrue(res[0]["device_owner"] == port3["device_owner"])
        res = db_api.port_find(self.context, scope=db_api.ALL,
                               device_owner=port1["device_owner"])
        self.assertTrue(len(res) == 2)
        self.assertTrue(res[0]["device_owner"] == res[1]["device_owner"] ==
                        port1["device_owner"])
        db_api.network_delete(self.context, net_mod)
        db_api.port_delete(self.context, port_mod1)
        db_api.port_delete(self.context, port_mod2)
        db_api.port_delete(self.context, port_mod3)


class QuarkCreatePortsRM9305(BaseFunctionalTest):
    PUBLICNET = "00000000-0000-0000-0000-000000000000"
    SERVICENET = "11111111-1111-1111-1111-111111111111"
    TENANT_NET = "tenant-id-net"
    OTHER_NET = "other-tenant-id-net"

    def setUp(self):
        super(QuarkCreatePortsRM9305, self).setUp()
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

    def test_RM9305_tenant_create_servicenet_port(self):
        port_1 = dict(port=dict(mac_address="AA:BB:CC:DD:EE:00",
                                network_id=self.SERVICENET,
                                tenant_id=self.context.tenant_id, device_id=2,
                                segment_id="bar",
                                name="Fake"))
        with self._stubs():
            self.plugin.create_port(self.context, port_1)

    def test_RM9305_tenant_create_publicnet_port(self):
        port_1 = dict(port=dict(mac_address="AA:BB:CC:DD:EE:00",
                                network_id=self.PUBLICNET,
                                tenant_id=self.context.tenant_id, device_id=3,
                                segment_id="bar",
                                name="Fake"))
        with self._stubs():
            self.plugin.create_port(self.context, port_1)

    def test_RM9305_tenant_create_tenants_port(self):
        port_1 = dict(port=dict(mac_address="AA:BB:CC:DD:EE:00",
                                network_id=self.TENANT_NET,
                                tenant_id=self.context.tenant_id, device_id=4,
                                name="Fake"))
        with self._stubs():
            self.plugin.create_port(self.context, port_1)

    def test_RM9305_tenant_create_other_tenants_port(self):
        port_1 = dict(port=dict(mac_address="AA:BB:CC:DD:EE:00",
                                network_id=self.OTHER_NET,
                                tenant_id=self.context.tenant_id, device_id=5,
                                name="Fake"))
        with self._stubs():
            with self.assertRaises(neutron_exc.NetworkNotFound):
                self.plugin.create_port(self.context, port_1)
