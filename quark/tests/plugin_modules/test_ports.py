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
from neutron.api.v2 import attributes as neutron_attrs
from neutron.common import exceptions
from oslo.config import cfg

from quark.db import models
from quark import exceptions as q_exc
from quark import network_strategy
from quark.plugin_modules import ports as quark_ports
from quark.tests import test_quark_plugin


class TestQuarkGetPorts(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, ports=None, addrs=None):
        port_models = []
        addr_models = None
        if addrs:
            addr_models = []
            for address in addrs:
                a = models.IPAddress()
                a.update(address)
                addr_models.append(a)

        if isinstance(ports, list):
            for port in ports:
                port_model = models.Port()
                port_model.update(port)
                if addr_models:
                    port_model.ip_addresses = addr_models
                port_models.append(port_model)
        elif ports is None:
            port_models = None
        else:
            port_model = models.Port()
            port_model.update(ports)
            if addr_models:
                port_model.ip_addresses = addr_models
            port_models = port_model

        db_mod = "quark.db.api"
        with contextlib.nested(
            mock.patch("%s.port_find" % db_mod)
        ) as (port_find,):
            port_find.return_value = port_models
            yield

    def test_port_list_no_ports(self):
        with self._stubs(ports=[]):
            ports = self.plugin.get_ports(self.context, filters=None,
                                          fields=None)
            self.assertEqual(ports, [])

    def test_port_list_with_device_owner_dhcp(self):
        ip = dict(id=1, address=3232235876, address_readable="192.168.1.100",
                  subnet_id=1, network_id=2, version=4)
        filters = {'network_id': ip['network_id'],
                   'device_owner': 'network:dhcp'}
        port = dict(mac_address="AA:BB:CC:DD:EE:FF", network_id=1,
                    tenant_id=self.context.tenant_id, device_id=2,
                    bridge="xenbr0", device_owner='network:dhcp')
        with self._stubs(ports=[port], addrs=[ip]):
            ports = self.plugin.get_ports(self.context, filters=filters,
                                          fields=None)
            self.assertEqual(len(ports), 1)
            self.assertEqual(ports[0]["device_owner"], "network:dhcp")

    def test_port_list_with_ports(self):
        ip = dict(id=1, address=3232235876, address_readable="192.168.1.100",
                  subnet_id=1, network_id=2, version=4)
        port = dict(mac_address="AA:BB:CC:DD:EE:FF", network_id=1,
                    tenant_id=self.context.tenant_id, device_id=2,
                    bridge="xenbr0")
        expected = {'status': "ACTIVE",
                    'device_owner': None,
                    'mac_address': 'AA:BB:CC:DD:EE:FF',
                    'network_id': 1,
                    'bridge': "xenbr0",
                    'tenant_id': self.context.tenant_id,
                    'admin_state_up': None,
                    'device_id': 2}
        with self._stubs(ports=[port], addrs=[ip]):
            ports = self.plugin.get_ports(self.context, filters=None,
                                          fields=None)
            self.assertEqual(len(ports), 1)
            fixed_ips = ports[0].pop("fixed_ips")
            for key in expected.keys():
                self.assertEqual(ports[0][key], expected[key])
            self.assertEqual(fixed_ips[0]["subnet_id"], ip["subnet_id"])
            self.assertEqual(fixed_ips[0]["ip_address"],
                             ip["address_readable"])

    def test_port_show(self):
        ip = dict(id=1, address=3232235876, address_readable="192.168.1.100",
                  subnet_id=1, network_id=2, version=4)
        port = dict(mac_address="AA:BB:CC:DD:EE:FF", network_id=1,
                    tenant_id=self.context.tenant_id, device_id=2)
        expected = {'status': "ACTIVE",
                    'device_owner': None,
                    'mac_address': 'AA:BB:CC:DD:EE:FF',
                    'network_id': 1,
                    'tenant_id': self.context.tenant_id,
                    'admin_state_up': None,
                    'device_id': 2}
        with self._stubs(ports=port, addrs=[ip]):
            result = self.plugin.get_port(self.context, 1)
            fixed_ips = result.pop("fixed_ips")
            for key in expected.keys():
                self.assertEqual(result[key], expected[key])
            self.assertEqual(fixed_ips[0]["subnet_id"], ip["subnet_id"])
            self.assertEqual(fixed_ips[0]["ip_address"],
                             ip["address_readable"])

    def test_port_show_with_int_mac(self):
        port = dict(mac_address=187723572702975L, network_id=1,
                    tenant_id=self.context.tenant_id, device_id=2)
        expected = {'status': "ACTIVE",
                    'device_owner': None,
                    'mac_address': 'AA:BB:CC:DD:EE:FF',
                    'network_id': 1,
                    'tenant_id': self.context.tenant_id,
                    'admin_state_up': None,
                    'fixed_ips': [],
                    'device_id': 2}
        with self._stubs(ports=port):
            result = self.plugin.get_port(self.context, 1)
            for key in expected.keys():
                self.assertEqual(result[key], expected[key])

    def test_port_show_not_found(self):
        with self._stubs(ports=None):
            with self.assertRaises(exceptions.PortNotFound):
                self.plugin.get_port(self.context, 1)


class TestQuarkGetPortsByIPAddress(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, ports=None, addr=None):
        addr_models = []

        for port in ports:
            ip_mod = models.IPAddress()
            ip_mod.update(addr)
            port_model = models.Port()
            port_model.update(port)

            ip_mod.ports = [port_model]
            addr_models.append(ip_mod)

        db_mod = "quark.db.api"
        with contextlib.nested(
            mock.patch("%s.port_find_by_ip_address" % db_mod)
        ) as (port_find_by_addr,):
            port_find_by_addr.return_value = addr_models
            yield

    def test_port_list_by_ip_address(self):
        ip = dict(id=1, address=3232235876, address_readable="192.168.1.100",
                  subnet_id=1, network_id=2, version=4)
        port = dict(mac_address="AA:BB:CC:DD:EE:FF", network_id=1,
                    tenant_id=self.context.tenant_id, device_id=2,
                    bridge="xenbr0", device_owner='network:dhcp')
        with self._stubs(ports=[port], addr=ip):
            admin_ctx = self.context.elevated()
            filters = {"ip_address": ["192.168.0.1"]}
            ports = self.plugin.get_ports(admin_ctx, filters=filters,
                                          fields=None)
            self.assertEqual(len(ports), 1)
            self.assertEqual(ports[0]["device_owner"], "network:dhcp")

    def test_port_list_by_ip_not_admin_raises(self):
        with self._stubs(ports=[]):
            filters = {"ip_address": ["192.168.0.1"]}
            with self.assertRaises(exceptions.NotAuthorized):
                self.plugin.get_ports(self.context, filters=filters,
                                      fields=None)


class TestQuarkCreatePortFailure(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, port=None, network=None, addr=None, mac=None):
        if network:
            network["network_plugin"] = "BASE"
            network["ipam_strategy"] = "ANY"
        port_model = models.Port()
        port_model.update(port)
        port_models = port_model

        db_mod = "quark.db.api"
        ipam = "quark.ipam.QuarkIpam"
        with contextlib.nested(
            mock.patch("%s.port_create" % db_mod),
            mock.patch("%s.network_find" % db_mod),
            mock.patch("%s.port_find" % db_mod),
            mock.patch("%s.allocate_ip_address" % ipam),
            mock.patch("%s.allocate_mac_address" % ipam),
            mock.patch("%s.port_count_all" % db_mod),
        ) as (port_create, net_find, port_find, alloc_ip, alloc_mac,
              port_count):
            port_create.return_value = port_models
            net_find.return_value = network
            port_find.return_value = models.Port()
            alloc_ip.return_value = addr
            alloc_mac.return_value = mac
            port_count.return_value = 0
            yield port_create

    def test_create_multiple_ports_on_same_net_and_device_id_bad_request(self):
        network = dict(id=1)
        ip = dict()
        mac = dict(address="AA:BB:CC:DD:EE:FF")
        port_1 = dict(port=dict(mac_address="AA:BB:CC:DD:EE:00", network_id=1,
                                tenant_id=self.context.tenant_id, device_id=1,
                                name="Fake"))
        port_2 = dict(port=dict(mac_address="AA:BB:CC:DD:EE:11", network_id=1,
                                tenant_id=self.context.tenant_id, device_id=1,
                                name="Faker"))

        with self._stubs(port=port_1, network=network, addr=ip, mac=mac):
            with self.assertRaises(exceptions.BadRequest):
                self.plugin.create_port(self.context, port_1)
                self.plugin.create_port(self.context, port_2)


class TestQuarkCreatePort(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, port=None, network=None, addr=None, mac=None,
               limit_checks=None):
        if network:
            network["network_plugin"] = "BASE"
            network["ipam_strategy"] = "ANY"
        port_model = models.Port()
        port_model.update(port)
        port_models = port_model

        db_mod = "quark.db.api"
        ipam = "quark.ipam.QuarkIpam"
        with contextlib.nested(
            mock.patch("%s.port_create" % db_mod),
            mock.patch("%s.network_find" % db_mod),
            mock.patch("%s.allocate_ip_address" % ipam),
            mock.patch("%s.allocate_mac_address" % ipam),
            mock.patch("%s.port_count_all" % db_mod),
            mock.patch("neutron.quota.QuotaEngine.limit_check")
        ) as (port_create, net_find, alloc_ip, alloc_mac, port_count,
              limit_check):
            port_create.return_value = port_models
            net_find.return_value = network
            alloc_ip.return_value = addr
            alloc_mac.return_value = mac
            port_count.return_value = 0
            if limit_checks:
                limit_check.side_effect = limit_checks
            yield port_create

    def test_create_port(self):
        network = dict(id=1)
        mac = dict(address="AA:BB:CC:DD:EE:FF")
        port_name = "foobar"
        ip = dict()
        port = dict(port=dict(mac_address=mac["address"], network_id=1,
                              tenant_id=self.context.tenant_id, device_id=2,
                              name=port_name))
        expected = {'status': "ACTIVE",
                    'name': port_name,
                    'device_owner': None,
                    'mac_address': mac["address"],
                    'network_id': network["id"],
                    'tenant_id': self.context.tenant_id,
                    'admin_state_up': None,
                    'fixed_ips': [],
                    'device_id': 2}
        with self._stubs(port=port["port"], network=network, addr=ip,
                         mac=mac) as port_create:
            result = self.plugin.create_port(self.context, port)
            self.assertTrue(port_create.called)
            for key in expected.keys():
                self.assertEqual(result[key], expected[key])

    def test_create_port_segment_id_on_unshared_net_ignored(self):
        network = dict(id=1)
        mac = dict(address="AA:BB:CC:DD:EE:FF")
        port_name = "foobar"
        ip = dict()
        port = dict(port=dict(mac_address=mac["address"], network_id=1,
                              tenant_id=self.context.tenant_id, device_id=2,
                              segment_id="cell01", name=port_name))
        expected = {'status': "ACTIVE",
                    'name': port_name,
                    'device_owner': None,
                    'mac_address': mac["address"],
                    'network_id': network["id"],
                    'tenant_id': self.context.tenant_id,
                    'admin_state_up': None,
                    'fixed_ips': [],
                    'device_id': 2}
        with self._stubs(port=port["port"], network=network, addr=ip,
                         mac=mac) as port_create:
            result = self.plugin.create_port(self.context, port)
            self.assertTrue(port_create.called)
            for key in expected.keys():
                self.assertEqual(result[key], expected[key])

    def test_create_port_mac_address_not_specified(self):
        network = dict(id=1)
        mac = dict(address="AA:BB:CC:DD:EE:FF")
        ip = dict()
        port = dict(port=dict(mac_address=mac["address"], network_id=1,
                              tenant_id=self.context.tenant_id, device_id=2))
        expected = {'status': "ACTIVE",
                    'device_owner': None,
                    'mac_address': mac["address"],
                    'network_id': network["id"],
                    'tenant_id': self.context.tenant_id,
                    'admin_state_up': None,
                    'fixed_ips': [],
                    'device_id': 2}
        with self._stubs(port=port["port"], network=network, addr=ip,
                         mac=mac) as port_create:
            port["port"]["mac_address"] = neutron_attrs.ATTR_NOT_SPECIFIED
            result = self.plugin.create_port(self.context, port)
            self.assertTrue(port_create.called)
            for key in expected.keys():
                self.assertEqual(result[key], expected[key])

    def test_create_port_fixed_ips(self):
        network = dict(id=1)
        mac = dict(address="AA:BB:CC:DD:EE:FF")
        ip = mock.MagicMock()
        ip.get = lambda x, *y: 1 if x == "subnet_id" else None
        ip.formatted = lambda: "192.168.10.45"
        fixed_ips = [dict(subnet_id=1, ip_address="192.168.10.45")]
        port = dict(port=dict(mac_address=mac["address"], network_id=1,
                              tenant_id=self.context.tenant_id, device_id=2,
                              fixed_ips=fixed_ips, ip_addresses=[ip]))
        expected = {'status': "ACTIVE",
                    'device_owner': None,
                    'mac_address': mac["address"],
                    'network_id': network["id"],
                    'tenant_id': self.context.tenant_id,
                    'admin_state_up': None,
                    'fixed_ips': fixed_ips,
                    'device_id': 2}
        with self._stubs(port=port["port"], network=network, addr=ip,
                         mac=mac) as port_create:
            result = self.plugin.create_port(self.context, port)
            self.assertTrue(port_create.called)
            for key in expected.keys():
                self.assertEqual(result[key], expected[key])

    def test_create_port_fixed_ips_bad_request(self):
        network = dict(id=1)
        mac = dict(address="AA:BB:CC:DD:EE:FF")
        ip = mock.MagicMock()
        ip.get = lambda x: 1 if x == "subnet_id" else None
        ip.formatted = lambda: "192.168.10.45"
        fixed_ips = [dict()]
        port = dict(port=dict(mac_address=mac["address"], network_id=1,
                              tenant_id=self.context.tenant_id, device_id=2,
                              fixed_ips=fixed_ips, ip_addresses=[ip]))
        with self._stubs(port=port["port"], network=network, addr=ip,
                         mac=mac):
            with self.assertRaises(exceptions.BadRequest):
                self.plugin.create_port(self.context, port)

    def test_create_port_no_network_found(self):
        port = dict(port=dict(network_id=1, tenant_id=self.context.tenant_id,
                              device_id=2))
        with self._stubs(network=None, port=port["port"]):
            with self.assertRaises(exceptions.NetworkNotFound):
                self.plugin.create_port(self.context, port)

    def test_create_port_security_groups_raises(self, groups=[1]):
        network = dict(id=1)
        mac = dict(address="AA:BB:CC:DD:EE:FF")
        port_name = "foobar"
        ip = dict()
        group = models.SecurityGroup()
        group.update({'id': 1, 'tenant_id': self.context.tenant_id,
                      'name': 'foo', 'description': 'bar'})
        port = dict(port=dict(mac_address=mac["address"], network_id=1,
                              tenant_id=self.context.tenant_id, device_id=2,
                              name=port_name, security_groups=[group]))
        with self._stubs(port=port["port"], network=network, addr=ip,
                         mac=mac):
            with mock.patch("quark.db.api.security_group_find"):
                with self.assertRaises(q_exc.SecurityGroupsNotImplemented):
                    self.plugin.create_port(self.context, port)


class TestQuarkPortCreateQuota(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, port=None, network=None, addr=None, mac=None):
        if network:
            network["network_plugin"] = "BASE"
            network["ipam_strategy"] = "ANY"
        port_model = models.Port()
        port_model.update(port)
        port_models = port_model

        db_mod = "quark.db.api"
        ipam = "quark.ipam.QuarkIpam"
        with contextlib.nested(
            mock.patch("%s.port_create" % db_mod),
            mock.patch("%s.network_find" % db_mod),
            mock.patch("%s.allocate_ip_address" % ipam),
            mock.patch("%s.allocate_mac_address" % ipam),
            mock.patch("quark.db.api.port_count_all"),
            mock.patch("neutron.quota.QuotaEngine.limit_check")
        ) as (port_create, net_find, alloc_ip, alloc_mac, port_count,
              limit_check):
            port_create.return_value = port_models
            net_find.return_value = network
            alloc_ip.return_value = addr
            alloc_mac.return_value = mac
            port_count.return_value = len(network["ports"])
            limit_check.side_effect = exceptions.OverQuota
            yield port_create

    def test_create_port_net_at_max(self):
        network = dict(id=1, ports=[models.Port()])
        mac = dict(address="AA:BB:CC:DD:EE:FF")
        port_name = "foobar"
        ip = dict()
        port = dict(port=dict(mac_address=mac["address"], network_id=1,
                              tenant_id=self.context.tenant_id, device_id=2,
                              name=port_name))
        with self._stubs(port=port["port"], network=network, addr=ip, mac=mac):
            with self.assertRaises(exceptions.OverQuota):
                self.plugin.create_port(self.context, port)


class TestQuarkUpdatePort(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, port, new_ips=None, parent_net=False):
        port_model = None
        if port:
            net_model = models.Network()
            net_model["network_plugin"] = "BASE"
            port_model = models.Port()
            port_model.network = net_model
            port_model.update(port)

        with contextlib.nested(
            mock.patch("quark.db.api.port_find"),
            mock.patch("quark.db.api.port_update"),
            mock.patch("quark.ipam.QuarkIpam.allocate_ip_address"),
            mock.patch("quark.ipam.QuarkIpam.deallocate_ips_by_port"),
            mock.patch("neutron.quota.QuotaEngine.limit_check"),
        ) as (port_find, port_update, alloc_ip, dealloc_ip, limit_check):
            port_find.return_value = port_model
            port_update.return_value = port_model
            if new_ips:
                alloc_ip.return_value = new_ips
            yield port_find, port_update, alloc_ip, dealloc_ip

    def test_update_port_not_found(self):
        with self._stubs(port=None):
            with self.assertRaises(exceptions.PortNotFound):
                self.plugin.update_port(self.context, 1, {})

    def test_update_port(self):
        with self._stubs(
            port=dict(id=1, name="myport")
        ) as (port_find, port_update, alloc_ip, dealloc_ip):
            new_port = dict(port=dict(name="ourport"))
            self.plugin.update_port(self.context, 1, new_port)
            self.assertEqual(port_find.call_count, 2)
            port_update.assert_called_once_with(
                self.context,
                port_find(),
                name="ourport",
                security_groups=[])

    def test_update_port_fixed_ip_bad_request(self):
        with self._stubs(
            port=dict(id=1, name="myport")
        ) as (port_find, port_update, alloc_ip, dealloc_ip):
            new_port = dict(port=dict(
                fixed_ips=[dict(subnet_id=None,
                                ip_address=None)]))
            with self.assertRaises(exceptions.BadRequest):
                self.plugin.update_port(self.context, 1, new_port)

    def test_update_port_fixed_ip(self):
        with self._stubs(
            port=dict(id=1, name="myport", mac_address="0:0:0:0:0:1")
        ) as (port_find, port_update, alloc_ip, dealloc_ip):
            new_port = dict(port=dict(
                fixed_ips=[dict(subnet_id=1,
                                ip_address="1.1.1.1")]))
            self.plugin.update_port(self.context, 1, new_port)
            self.assertEqual(alloc_ip.call_count, 1)

    def test_update_port_fixed_ip_no_subnet_raises(self):
        with self._stubs(
            port=dict(id=1, name="myport", mac_address="0:0:0:0:0:1")
        ) as (port_find, port_update, alloc_ip, dealloc_ip):
            new_port = dict(port=dict(
                fixed_ips=[dict(ip_address="1.1.1.1")]))
            with self.assertRaises(exceptions.BadRequest):
                self.plugin.update_port(self.context, 1, new_port)

    def test_update_port_fixed_ip_subnet_only_allocates_ip(self):
        with self._stubs(
            port=dict(id=1, name="myport", mac_address="0:0:0:0:0:1")
        ) as (port_find, port_update, alloc_ip, dealloc_ip):
            new_port = dict(port=dict(
                fixed_ips=[dict(subnet_id=1)]))
            self.plugin.update_port(self.context, 1, new_port)
            self.assertEqual(alloc_ip.call_count, 1)

    def test_update_port_fixed_ip_allocs_new_deallocs_existing(self):
        addr_dict = {"address": 0, "address_readable": "0.0.0.0"}
        addr = models.IPAddress()
        addr.update(addr_dict)
        new_addr_dict = {"address": 16843009, "address_readable": "1.1.1.1"}
        new_addr = models.IPAddress()
        new_addr.update(new_addr_dict)

        with self._stubs(
            port=dict(id=1, name="myport", mac_address="0:0:0:0:0:1",
                      ip_addresses=[addr]),
            new_ips=[new_addr]
        ) as (port_find, port_update, alloc_ip, dealloc_ip):
            new_port = dict(port=dict(
                fixed_ips=[dict(subnet_id=1,
                                ip_address=new_addr["address_readable"])]))
            self.plugin.update_port(self.context, 1, new_port)
            self.assertEqual(alloc_ip.call_count, 1)


class TestQuarkUpdatePortSecurityGroups(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, port, new_ips=None, parent_net=False):
        port_model = None
        sg_mod = models.SecurityGroup()
        if port:
            net_model = models.Network()
            net_model["network_plugin"] = "BASE"
            port_model = models.Port()
            port_model.network = net_model
            port_model.update(port)
            port_model["security_groups"].append(sg_mod)

        with contextlib.nested(
            mock.patch("quark.db.api.port_find"),
            mock.patch("quark.db.api.port_update"),
            mock.patch("quark.ipam.QuarkIpam.allocate_ip_address"),
            mock.patch("quark.ipam.QuarkIpam.deallocate_ips_by_port"),
            mock.patch("neutron.quota.QuotaEngine.limit_check"),
            mock.patch("quark.plugin_modules.ports.STRATEGY"
                       ".is_parent_network"),
            mock.patch("quark.db.api.security_group_find")
        ) as (port_find, port_update, alloc_ip, dealloc_ip, limit_check,
              net_strat, sg_find):
            port_find.return_value = port_model
            port_update.return_value = port_model
            if new_ips:
                alloc_ip.return_value = new_ips
            net_strat.return_value = parent_net
            sg_find.return_value = sg_mod
            yield port_find, port_update, alloc_ip, dealloc_ip, sg_find

    def test_update_port_security_groups_on_tenant_net_raises(self):
        with self._stubs(
            port=dict(id=1)
        ) as (port_find, port_update, alloc_ip, dealloc_ip, sg_find):
            new_port = dict(port=dict(name="ourport",
                                      security_groups=[1]))
            with self.assertRaises(
                    q_exc.TenantNetworkSecurityGroupsNotImplemented):
                self.plugin.update_port(self.context, 1, new_port)

    def test_update_port_security_groups(self):
        with self._stubs(
            port=dict(id=1), parent_net=True
        ) as (port_find, port_update, alloc_ip, dealloc_ip, sg_find):
            new_port = dict(port=dict(name="ourport",
                                      security_groups=[1]))
            port = self.plugin.update_port(self.context, 1, new_port)
            port_update.assert_called_once_with(
                self.context,
                port_find(),
                name="ourport",
                security_groups=[sg_find()])
            self.assertEqual(sg_find()["id"], port["security_groups"][0])


class TestQuarkUpdatePortSetsIps(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, port, new_ips=None):
        def alloc_mock(kls, context, addresses, *args, **kwargs):
            addresses.extend(new_ips)
            self.called = True

        port_model = None
        if port:
            net_model = models.Network()
            net_model["network_plugin"] = "BASE"
            port_model = models.Port()
            port_model['network'] = net_model
            port_model.update(port)
        with contextlib.nested(
            mock.patch("quark.db.api.port_find"),
            mock.patch("quark.db.api.port_update"),
            mock.patch("quark.ipam.QuarkIpam.deallocate_ips_by_port"),
            mock.patch("neutron.quota.QuotaEngine.limit_check")
        ) as (port_find, port_update, dealloc_ip, limit_check):
            port_find.return_value = port_model
            port_update.return_value = port_model
            alloc_ip = mock.patch("quark.ipam.QuarkIpam.allocate_ip_address",
                                  new=alloc_mock)
            alloc_ip.start()
            yield port_find, port_update, alloc_ip, dealloc_ip
            alloc_ip.stop()

    def test_update_port_fixed_ip_subnet_only_allocates_ip(self):
        self.called = False
        new_addr_dict = {"address": 16843009, "address_readable": "1.1.1.1"}
        new_addr = models.IPAddress()
        new_addr.update(new_addr_dict)
        with self._stubs(
            port=dict(id=1, name="myport", mac_address="0:0:0:0:0:1"),
            new_ips=[new_addr]
        ) as (port_find, port_update, alloc_ip, dealloc_ip):
            new_port = dict(port=dict(
                fixed_ips=[dict(subnet_id=1)]))
            self.plugin.update_port(self.context, 1, new_port)
            self.assertTrue(self.called)


class TestQuarkPostUpdatePort(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, port, addr, addr2=None, port_ips=None):
        port_model = None
        addr_model = None
        addr_model2 = None
        if port:
            port_model = models.Port()
            port_model.update(port)
            if port_ips:
                port_model["ip_addresses"] = []
                for ip in port_ips:
                    ip_mod = models.IPAddress()
                    ip_mod.update(ip)
                    port_model["ip_addresses"].append(ip_mod)
            net_model = models.Network()
            net_model["ipam_strategy"] = "ANY"
            port_model["network"] = net_model

        if addr:
            addr_model = models.IPAddress()
            addr_model.update(addr)
        if addr2:
            addr_model2 = models.IPAddress()
            addr_model2.update(addr2)
        with contextlib.nested(
            mock.patch("quark.db.api.port_find"),
            mock.patch("quark.ipam.QuarkIpam.allocate_ip_address"),
            mock.patch("quark.db.api.ip_address_find"),
        ) as (port_find, alloc_ip, ip_find):
            port_find.return_value = port_model
            alloc_ip.return_value = addr_model2 if addr_model2 else addr_model
            ip_find.return_value = addr_model
            yield port_find, alloc_ip, ip_find

    def test_post_update_port_no_ports(self):
        with self._stubs(port=None, addr=None):
            with self.assertRaises(exceptions.PortNotFound):
                self.plugin.post_update_port(self.context, 1,
                                             {"port": {"network_id": 1}})

    def test_post_update_port_fixed_ips_empty_body(self):
        port = dict(port=dict(network_id=1, tenant_id=self.context.tenant_id,
                              device_id=2))
        with self._stubs(port=port, addr=None):
            with self.assertRaises(exceptions.BadRequest):
                self.plugin.post_update_port(self.context, 1, {})
            with self.assertRaises(exceptions.BadRequest):
                self.plugin.post_update_port(self.context, 1, {"port": {}})

    def test_post_update_port_fixed_ips_ip(self):
        new_port_ip = dict(port=dict(fixed_ips=[dict()]))
        port = dict(port=dict(network_id=1, tenant_id=self.context.tenant_id,
                              device_id=2))
        ip = dict(id=1, address=3232235876, address_readable="192.168.1.100",
                  subnet_id=1, network_id=2, version=4, deallocated=True)
        with self._stubs(port=port, addr=ip) as (port_find, alloc_ip, ip_find):
            response = self.plugin.post_update_port(self.context, 1,
                                                    new_port_ip)
            self.assertEqual(port_find.call_count, 1)
            self.assertEqual(alloc_ip.call_count, 1)
            self.assertEqual(ip_find.call_count, 0)
            self.assertEqual(response["fixed_ips"][0]["ip_address"],
                             "192.168.1.100")

    def test_post_update_port_fixed_ips_ip_id(self):
        new_port_ip = dict(port=dict(fixed_ips=[dict(ip_id=1)]))
        port = dict(port=dict(network_id=1, tenant_id=self.context.tenant_id,
                              device_id=2))
        ip = dict(id=1, address=3232235876, address_readable="192.168.1.100",
                  subnet_id=1, network_id=2, version=4, deallocated=True)
        with self._stubs(port=port, addr=ip) as (port_find, alloc_ip, ip_find):
            response = self.plugin.post_update_port(self.context, 1,
                                                    new_port_ip)
            self.assertEqual(port_find.call_count, 1)
            self.assertEqual(alloc_ip.call_count, 0)
            self.assertEqual(ip_find.call_count, 1)
            self.assertEqual(response["fixed_ips"][0]["ip_address"],
                             "192.168.1.100")

    def test_post_update_port_fixed_ips_ip_address_exists(self):
        new_port_ip = dict(port=dict(fixed_ips=[dict(
            ip_address="192.168.1.100")]))
        port = dict(port=dict(network_id=1, tenant_id=self.context.tenant_id,
                              device_id=2))
        ip = dict(id=1, address=3232235876, address_readable="192.168.1.100",
                  subnet_id=1, network_id=2, version=4, deallocated=True)
        with self._stubs(port=port, addr=ip) as (port_find, alloc_ip, ip_find):
            response = self.plugin.post_update_port(self.context, 1,
                                                    new_port_ip)
            self.assertEqual(port_find.call_count, 1)
            self.assertEqual(alloc_ip.call_count, 0)
            self.assertEqual(ip_find.call_count, 1)
            self.assertEqual(response["fixed_ips"][0]["ip_address"],
                             "192.168.1.100")

    def test_post_update_port_fixed_ips_ip_address_doesnt_exist(self):
        new_port_ip = dict(port=dict(fixed_ips=[dict(
            ip_address="192.168.1.101")]))
        port = dict(port=dict(network_id=1, tenant_id=self.context.tenant_id,
                              device_id=2))
        ip = dict(id=1, address=3232235876, address_readable="192.168.1.101",
                  subnet_id=1, network_id=2, version=4, deallocated=True)
        with self._stubs(port=port, addr=None, addr2=ip) as (port_find,
                                                             alloc_ip,
                                                             ip_find):
            response = self.plugin.post_update_port(self.context, 1,
                                                    new_port_ip)
            self.assertEqual(port_find.call_count, 1)
            self.assertEqual(alloc_ip.call_count, 1)
            self.assertEqual(ip_find.call_count, 1)
            self.assertEqual(response["fixed_ips"][0]["ip_address"],
                             "192.168.1.101")

    def test_post_update_port_already_has_ip(self):
        new_port_ip = dict(port=dict(fixed_ips=[dict()]))
        port = dict(port=dict(network_id=1, tenant_id=self.context.tenant_id,
                              device_id=2))
        ip = dict(id=1, address=3232235876, address_readable="192.168.1.100",
                  subnet_id=1, network_id=2, version=4, deallocated=True)
        port_ips = [ip]
        with self._stubs(port=port, addr=ip, port_ips=port_ips) as (port_find,
                                                                    alloc_ip,
                                                                    ip_find):
            response = self.plugin.post_update_port(self.context, 1,
                                                    new_port_ip)
            self.assertEqual(port_find.call_count, 1)
            self.assertEqual(alloc_ip.call_count, 1)
            self.assertEqual(ip_find.call_count, 0)
            self.assertEqual(response["fixed_ips"][0]["ip_address"],
                             "192.168.1.100")


class TestQuarkCreatePortOnSharedNetworks(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, port=None, network=None, addr=None, mac=None):
        self.strategy = {"public_network":
                         {"required": True,
                          "bridge": "xenbr0",
                          "children": {"nova": "child_net"}}}
        strategy_json = json.dumps(self.strategy)
        quark_ports.STRATEGY = network_strategy.JSONStrategy(strategy_json)

        if network:
            network["network_plugin"] = "BASE"
            network["ipam_strategy"] = "ANY"
        port_model = models.Port()
        port_model.update(port)
        port_models = port_model

        db_mod = "quark.db.api"
        ipam = "quark.ipam.QuarkIpam"
        with contextlib.nested(
            mock.patch("%s.port_create" % db_mod),
            mock.patch("%s.network_find" % db_mod),
            mock.patch("%s.allocate_ip_address" % ipam),
            mock.patch("%s.allocate_mac_address" % ipam),
            mock.patch("neutron.quota.QuotaEngine.limit_check")
        ) as (port_create, net_find, alloc_ip, alloc_mac, limit_check):
            port_create.return_value = port_models
            net_find.return_value = network
            alloc_ip.return_value = addr
            alloc_mac.return_value = mac
            yield port_create

    def test_create_port_shared_net_no_quota_check(self):
        network = dict(id=1, ports=[models.Port()])
        mac = dict(address="AA:BB:CC:DD:EE:FF")
        port_name = "foobar"
        ip = dict()
        port = dict(port=dict(mac_address=mac["address"],
                              network_id="public_network",
                              tenant_id=self.context.tenant_id, device_id=2,
                              segment_id="cell01",
                              name=port_name))
        with self._stubs(port=port["port"], network=network, addr=ip, mac=mac):
            try:
                self.plugin.create_port(self.context, port)
            except Exception:
                self.fail("create_port raised OverQuota")

    def test_create_port_shared_net_no_segment_id_fails(self):
        network = dict(id=1, ports=[models.Port()])
        mac = dict(address="AA:BB:CC:DD:EE:FF")
        port_name = "foobar"
        ip = dict()
        port = dict(port=dict(mac_address=mac["address"],
                              network_id="public_network",
                              tenant_id=self.context.tenant_id, device_id=2,
                              name=port_name))
        with self._stubs(port=port["port"], network=network, addr=ip, mac=mac):
            with self.assertRaises(q_exc.AmbiguousNetworkId):
                self.plugin.create_port(self.context, port)


class TestQuarkGetPortCount(test_quark_plugin.TestQuarkPlugin):
    def test_get_port_count(self):
        """This isn't really testable."""
        with mock.patch("quark.db.api.port_count_all"):
            self.plugin.get_ports_count(self.context, {})


class TestQuarkDeletePort(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, port=None, addr=None, mac=None):
        port_models = None
        if port:
            net_model = models.Network()
            net_model["network_plugin"] = "BASE"
            net_model["ipam_strategy"] = "ANY"
            port_model = models.Port()
            port_model.update(port)
            port_model.network = net_model
            port_models = port_model

        db_mod = "quark.db.api"
        ipam = "quark.ipam.QuarkIpam"
        with contextlib.nested(
            mock.patch("%s.port_find" % db_mod),
            mock.patch("%s.deallocate_ips_by_port" % ipam),
            mock.patch("%s.deallocate_mac_address" % ipam),
            mock.patch("%s.port_delete" % db_mod),
            mock.patch("quark.drivers.base.BaseDriver.delete_port")
        ) as (port_find, dealloc_ip, dealloc_mac, db_port_del,
              driver_port_del):
            port_find.return_value = port_models
            dealloc_ip.return_value = addr
            dealloc_mac.return_value = mac
            yield db_port_del, driver_port_del

    def test_port_delete(self):
        port = dict(port=dict(network_id=1, tenant_id=self.context.tenant_id,
                              device_id=2, mac_address="AA:BB:CC:DD:EE:FF",
                              backend_key="foo"))
        with self._stubs(port=port["port"]) as (db_port_del, driver_port_del):
            self.plugin.delete_port(self.context, 1)
            self.assertTrue(db_port_del.called)
            driver_port_del.assert_called_with(self.context, "foo")

    def test_port_delete_port_not_found_fails(self):
        with self._stubs(port=None) as (db_port_del, driver_port_del):
            with self.assertRaises(exceptions.PortNotFound):
                self.plugin.delete_port(self.context, 1)


class TestPortDiagnose(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, port, list_format=False):
        port_res = None
        if port:
            network_mod = models.Network()
            port_mod = models.Port()
            port_mod.update(port)
            network_mod["network_plugin"] = "UNMANAGED"
            port_mod.network = network_mod
            port_res = port_mod
            if list_format:
                ports = mock.MagicMock()
                ports.all.return_value = [port_mod]
                port_res = ports

        with mock.patch("quark.db.api.port_find") as port_find:
            port_find.return_value = port_res
            yield

    def test_port_diagnose(self):
        ip = dict(id=1, address=3232235876, address_readable="192.168.1.100",
                  subnet_id=1, network_id=2, version=4)
        fixed_ips = [{"subnet_id": ip["subnet_id"],
                      "ip_address": ip["address_readable"]}]
        port = dict(port=dict(network_id=1, tenant_id=self.context.tenant_id,
                              device_id=2, mac_address="AA:BB:CC:DD:EE:FF",
                              backend_key="foo", fixed_ips=fixed_ips,
                              network_plugin="UNMANAGED"))
        with self._stubs(port=port):
            diag = self.plugin.diagnose_port(self.context.elevated(), 1, [])
            ports = diag["ports"]
            # All none because we're using the unmanaged driver, which
            # doesn't do anything with these
            self.assertEqual(ports["status"], "ACTIVE")
            self.assertEqual(ports["device_owner"], None)
            self.assertEqual(ports["fixed_ips"], [])
            self.assertEqual(ports["security_groups"], [])
            self.assertEqual(ports["device_id"], None)
            self.assertEqual(ports["admin_state_up"], None)
            self.assertEqual(ports["network_id"], None)
            self.assertEqual(ports["tenant_id"], None)
            self.assertEqual(ports["mac_address"], None)

    def test_port_diagnose_with_wildcard(self):
        ip = dict(id=1, address=3232235876, address_readable="192.168.1.100",
                  subnet_id=1, network_id=2, version=4)
        fixed_ips = [{"subnet_id": ip["subnet_id"],
                      "ip_address": ip["address_readable"]}]
        port = dict(port=dict(network_id=1, tenant_id=self.context.tenant_id,
                              device_id=2, mac_address="AA:BB:CC:DD:EE:FF",
                              backend_key="foo", fixed_ips=fixed_ips,
                              network_plugin="UNMANAGED"))
        with self._stubs(port=port, list_format=True):
            diag = self.plugin.diagnose_port(self.context.elevated(), '*', [])
            ports = diag["ports"]
            # All none because we're using the unmanaged driver, which
            # doesn't do anything with these
            self.assertEqual(ports[0]["status"], "ACTIVE")
            self.assertEqual(ports[0]["device_owner"], None)
            self.assertEqual(ports[0]["fixed_ips"], [])
            self.assertEqual(ports[0]["security_groups"], [])
            self.assertEqual(ports[0]["device_id"], None)
            self.assertEqual(ports[0]["admin_state_up"], None)
            self.assertEqual(ports[0]["network_id"], None)
            self.assertEqual(ports[0]["tenant_id"], None)
            self.assertEqual(ports[0]["mac_address"], None)

    def test_port_diagnose_with_config_field(self):
        ip = dict(id=1, address=3232235876, address_readable="192.168.1.100",
                  subnet_id=1, network_id=2, version=4)
        fixed_ips = [{"subnet_id": ip["subnet_id"],
                      "ip_address": ip["address_readable"]}]
        port = dict(port=dict(network_id=1, tenant_id=self.context.tenant_id,
                              device_id=2, mac_address="AA:BB:CC:DD:EE:FF",
                              backend_key="foo", fixed_ips=fixed_ips,
                              network_plugin="UNMANAGED"))
        with self._stubs(port=port, list_format=True):
            diag = self.plugin.diagnose_port(self.context.elevated(), '*',
                                             ["config"])
            ports = diag["ports"]
            # All none because we're using the unmanaged driver, which
            # doesn't do anything with these
            self.assertEqual(ports[0]["status"], "ACTIVE")
            self.assertEqual(ports[0]["device_owner"], None)
            self.assertEqual(ports[0]["fixed_ips"], [])
            self.assertEqual(ports[0]["security_groups"], [])
            self.assertEqual(ports[0]["device_id"], None)
            self.assertEqual(ports[0]["admin_state_up"], None)
            self.assertEqual(ports[0]["network_id"], None)
            self.assertEqual(ports[0]["tenant_id"], None)
            self.assertEqual(ports[0]["mac_address"], None)

    def test_port_diagnose_no_port_raises(self):
        with self._stubs(port=None):
            with self.assertRaises(exceptions.PortNotFound):
                self.plugin.diagnose_port(self.context.elevated(), 1, [])

    def test_port_diagnose_not_authorized(self):
        with self._stubs(port=None):
            with self.assertRaises(exceptions.NotAuthorized):
                self.plugin.diagnose_port(self.context, 1, [])


class TestPortBadNetworkPlugin(test_quark_plugin.TestQuarkPlugin):
    def test_create_port_with_bad_network_plugin_fails(self):
        network_dict = dict(id=1)
        port_name = "foobar"
        mac = dict(address="AA:BB:CC:DD:EE:FF")
        port = dict(port=dict(mac_address=mac["address"], network_id=1,
                              tenant_id=self.context.tenant_id, device_id=2,
                              name=port_name))
        network = models.Network()
        network.update(network_dict)
        network["network_plugin"] = "FAIL"
        port_model = models.Port()
        port_model.update(port)
        port_models = port_model

        db_mod = "quark.db.api"
        ipam = "quark.ipam.QuarkIpam"
        with contextlib.nested(
            mock.patch("%s.port_create" % db_mod),
            mock.patch("%s.network_find" % db_mod),
            mock.patch("%s.allocate_ip_address" % ipam),
            mock.patch("%s.allocate_mac_address" % ipam),
        ) as (port_create, net_find, alloc_ip, alloc_mac):
            port_create.return_value = port_models
            net_find.return_value = network
            alloc_ip.return_value = {}
            alloc_mac.return_value = mac

            with self.assertRaises(Exception):  # noqa
                self.plugin.create_port(self.context, port)


class TestQuarkPortCreateFiltering(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, network=None, addr=None, mac=None):
        network["network_plugin"] = "BASE"
        network["ipam_strategy"] = "ANY"

        db_mod = "quark.db.api"
        ipam = "quark.ipam.QuarkIpam"

        with contextlib.nested(
            mock.patch("%s.port_create" % db_mod),
            mock.patch("%s.network_find" % db_mod),
            mock.patch("%s.allocate_ip_address" % ipam),
            mock.patch("%s.allocate_mac_address" % ipam),
            mock.patch("neutron.openstack.common.uuidutils.generate_uuid"),
            mock.patch("quark.plugin_views._make_port_dict"),
            mock.patch("%s.port_count_all" % db_mod),
            mock.patch("neutron.quota.QuotaEngine.limit_check")
        ) as (port_create, net_find, alloc_ip, alloc_mac, gen_uuid, make_port,
              port_count, limit_check):
            net_find.return_value = network
            alloc_ip.return_value = addr
            alloc_mac.return_value = mac
            gen_uuid.return_value = 1
            port_count.return_value = 0
            yield port_create, alloc_mac, net_find

    def test_create_port_attribute_filtering(self):
        network = dict(id=1)
        mac = dict(address="AA:BB:CC:DD:EE:FF")
        port_name = "foobar"
        ip = dict()
        port = dict(port=dict(mac_address=mac["address"], network_id=1,
                              tenant_id=self.context.tenant_id, device_id=2,
                              name=port_name, device_owner="quark_tests",
                              bridge="quark_bridge", admin_state_up=False))

        port_create_dict = {}
        port_create_dict["port"] = port["port"].copy()
        port_create_dict["port"]["mac_address"] = "DE:AD:BE:EF:00:00"
        port_create_dict["port"]["device_owner"] = "ignored"
        port_create_dict["port"]["bridge"] = "ignored"
        port_create_dict["port"]["admin_state_up"] = "ignored"

        with self._stubs(network=network, addr=ip,
                         mac=mac) as (port_create, alloc_mac, net_find):
            self.plugin.create_port(self.context, port_create_dict)
            alloc_mac.assert_called_once_with(
                self.context, network["id"], 1,
                cfg.CONF.QUARK.ipam_reuse_after,
                mac_address=None)
            port_create.assert_called_once_with(
                self.context, addresses=[], network_id=network["id"],
                tenant_id="fake", uuid=1, name="foobar",
                mac_address=alloc_mac()["address"], backend_key=1, id=1,
                security_groups=[], device_id=2)

    def test_create_port_attribute_filtering_admin(self):
        network = dict(id=1)
        mac = dict(address="AA:BB:CC:DD:EE:FF")
        port_name = "foobar"
        ip = dict()

        port = dict(port=dict(mac_address=mac["address"], network_id=1,
                              tenant_id=self.context.tenant_id, device_id=2,
                              name=port_name, device_owner="quark_tests",
                              bridge="quark_bridge", admin_state_up=False))

        expected_mac = "DE:AD:BE:EF:00:00"
        expected_bridge = "new_bridge"
        expected_device_owner = "new_device_owner"
        expected_admin_state = "new_state"

        port_create_dict = {}
        port_create_dict["port"] = port["port"].copy()
        port_create_dict["port"]["mac_address"] = expected_mac
        port_create_dict["port"]["device_owner"] = expected_device_owner
        port_create_dict["port"]["bridge"] = expected_bridge
        port_create_dict["port"]["admin_state_up"] = expected_admin_state

        admin_ctx = self.context.elevated()
        with self._stubs(network=network, addr=ip,
                         mac=mac) as (port_create, alloc_mac, net_find):
            self.plugin.create_port(admin_ctx, port_create_dict)

            alloc_mac.assert_called_once_with(
                admin_ctx, network["id"], 1,
                cfg.CONF.QUARK.ipam_reuse_after,
                mac_address=expected_mac)

            port_create.assert_called_once_with(
                admin_ctx, bridge=expected_bridge, uuid=1, name="foobar",
                admin_state_up=expected_admin_state, network_id=1,
                tenant_id="fake", id=1, device_owner=expected_device_owner,
                mac_address=mac["address"], device_id=2, backend_key=1,
                security_groups=[], addresses=[])


class TestQuarkPortUpdateFiltering(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self):
        with contextlib.nested(
            mock.patch("quark.db.api.port_find"),
            mock.patch("quark.db.api.port_update"),
            mock.patch("quark.drivers.registry.DriverRegistry.get_driver"),
            mock.patch("quark.plugin_views._make_port_dict"),
            mock.patch("neutron.quota.QuotaEngine.limit_check")
        ) as (port_find, port_update, get_driver, make_port, limit_check):
            yield port_find, port_update

    def test_update_port_attribute_filtering(self):
        new_port = {}
        new_port["port"] = {
            "mac_address": "DD:EE:FF:00:00:00", "device_owner": "new_owner",
            "bridge": "new_bridge", "admin_state_up": False, "device_id": 3,
            "network_id": 10, "backend_key": 1234, "name": "new_name"}

        with self._stubs() as (port_find, port_update):
            self.plugin.update_port(self.context, 1, new_port)
            port_update.assert_called_once_with(
                self.context,
                port_find(),
                name="new_name",
                security_groups=[])

    def test_update_port_attribute_filtering_admin(self):
        new_port = {}
        new_port["port"] = {
            "mac_address": "DD:EE:FF:00:00:00", "device_owner": "new_owner",
            "bridge": "new_bridge", "admin_state_up": False, "device_id": 3,
            "network_id": 10, "backend_key": 1234, "name": "new_name"}

        admin_ctx = self.context.elevated()
        with self._stubs() as (port_find, port_update):
            self.plugin.update_port(admin_ctx, 1, new_port)
            port_update.assert_called_once_with(
                admin_ctx,
                port_find(),
                name="new_name",
                bridge=new_port["port"]["bridge"],
                admin_state_up=new_port["port"]["admin_state_up"],
                device_owner=new_port["port"]["device_owner"],
                mac_address=new_port["port"]["mac_address"],
                device_id=new_port["port"]["device_id"],
                security_groups=[])
