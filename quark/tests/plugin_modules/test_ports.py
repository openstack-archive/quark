# Copyright 2013 Rackspace Hosting Inc.
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
import netaddr
from neutron.api.v2 import attributes as neutron_attrs
from neutron_lib import exceptions as n_exc
from oslo_config import cfg

from quark.db import models
from quark.drivers import registry
from quark import exceptions as q_exc
from quark import network_strategy
from quark.plugin_modules import ports as quark_ports
from quark import plugin_views
from quark import tags
from quark.tests import test_quark_plugin


class TestQuarkGetPorts(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, ports=None, addrs=None):
        port_models = []
        addr_models = None
        if addrs:
            addr_models = []
            for address in addrs:
                a = models.IPAddress(**address)
                addr_models.append(a)

        if isinstance(ports, list):
            for port in ports:
                port_model = models.Port(**port)
                if addr_models:
                    port_model.ip_addresses = addr_models
                port_models.append(port_model)
        elif ports is None:
            port_models = None
        else:
            port_model = models.Port(**ports)
            if addr_models:
                port_model.ip_addresses = addr_models
            port_models = port_model

        with contextlib.nested(
            mock.patch("quark.db.api.port_find")
        ) as (port_find,):
            port_find.return_value = port_models
            yield

    def test_port_list_no_ports(self):
        with self._stubs(ports=[]):
            ports = self.plugin.get_ports(self.context, filters=None,
                                          fields=None)
            self.assertEqual(ports, [])

    def test_port_list_with_device_owner_dhcp(self):
        ip = dict(id=1, address=netaddr.IPAddress("192.168.1.100").value,
                  address_readable="192.168.1.100", subnet_id=1, network_id=2,
                  version=4)
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
        ip = dict(id=1, address=netaddr.IPAddress("192.168.1.100").value,
                  address_readable="192.168.1.100", subnet_id=1, network_id=2,
                  version=4)
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

    def test_port_show_with_int_mac(self):
        port = dict(mac_address=int('AABBCCDDEEFF', 16), network_id=1,
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
            with self.assertRaises(n_exc.PortNotFound):
                self.plugin.get_port(self.context, 1)

    def test_port_show_vlan_id(self):
        """Prove VLAN IDs are included in port information when available."""
        port_tags = [tags.VlanTag().serialize(5)]
        port = dict(mac_address=int('AABBCCDDEEFF', 16), network_id=1,
                    tenant_id=self.context.tenant_id, device_id=2,
                    tags=port_tags)
        expected = {'status': "ACTIVE",
                    'device_owner': None,
                    'mac_address': 'AA:BB:CC:DD:EE:FF',
                    'network_id': 1,
                    'tenant_id': self.context.tenant_id,
                    'admin_state_up': None,
                    'fixed_ips': [],
                    'device_id': 2,
                    'vlan_id': '5'}
        with self._stubs(ports=port):
            result = self.plugin.get_port(self.context, 1)
            for key in expected.keys():
                self.assertEqual(result[key], expected[key])

    def test_port_show_invalid_vlan_id(self):
        """Prove VLAN IDs are included in port information when available."""
        port_tags = [tags.VlanTag().serialize('invalid')]
        port = dict(mac_address=int('AABBCCDDEEFF', 16), network_id=1,
                    tenant_id=self.context.tenant_id, device_id=2,
                    tags=port_tags)
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


class TestQuarkGetPortsProviderSubnetIds(test_quark_plugin.TestQuarkPlugin):

    def setUp(self):
        super(TestQuarkGetPortsProviderSubnetIds, self).setUp()
        self.strategy = {
            "1": {
                "bridge": "publicnet",
                "subnets": {
                    "4": "v4-provider-subnet-id",
                    "6": "v6-provider-subnet-id"
                }
            }
        }
        self.strategy_json = json.dumps(self.strategy)
        self.old = plugin_views.STRATEGY
        plugin_views.STRATEGY = network_strategy.JSONStrategy(
            self.strategy_json)
        cfg.CONF.set_override("default_net_strategy", self.strategy_json,
                              "QUARK")

    def tearDown(self):
        plugin_views.STRATEGY = self.old

    def _port_associate_stub(self, ports, address, **kwargs):
        if not isinstance(ports, list):
            ports = [ports]

        for port in ports:
            assoc = models.PortIpAssociation()
            assoc.port_id = port.id
            assoc.ip_address_id = address.id
            assoc.port = port
            assoc.ip_address = address
            assoc.enabled = address.address_type == "fixed"
        return address

    @contextlib.contextmanager
    def _stubs(self, ports=None, addrs=None):
        port_models = []
        addr_models = None
        if addrs:
            addr_models = []
            for address in addrs:
                a = models.IPAddress(**address)
                addr_models.append(a)

        if isinstance(ports, list):
            for port in ports:
                port_model = models.Port(**port)
                if addr_models:
                    port_model.ip_addresses = addr_models
                    for addr_model in addr_models:
                        self._port_associate_stub(
                            port_model, addr_model)
                port_models.append(port_model)
        elif ports is None:
            port_models = None
        else:
            port_model = models.Port(**ports)
            if addr_models:
                port_model.ip_addresses = addr_models
                for addr_model in addr_models:
                        self._port_associate_stub(
                            port_model, addr_model)
            port_models = port_model

        with contextlib.nested(
            mock.patch("quark.db.api.port_find")
        ) as (port_find,):
            port_find.return_value = port_models
            yield

    def test_port_show_with_provider_subnet_ids(self):
        """Prove provider subnets ids are shown on the port object."""
        ip = dict(id=1, address=netaddr.IPAddress("192.168.1.100").value,
                  address_readable="192.168.1.100", subnet_id="1",
                  network_id="1", version=4, address_type="fixed")
        port = dict(mac_address=int('AABBCCDDEEFF', 16), network_id="1",
                    tenant_id=self.context.tenant_id, device_id=2)
        expected = {'status': "ACTIVE",
                    'device_owner': None,
                    'mac_address': 'AA:BB:CC:DD:EE:FF',
                    'network_id': "1",
                    'tenant_id': self.context.tenant_id,
                    'admin_state_up': None,
                    'fixed_ips': [
                        {'subnet_id': 'v4-provider-subnet-id', 'enabled': True,
                         'ip_address': '192.168.1.100'}
                    ],
                    'device_id': 2}
        with self._stubs(ports=port, addrs=[ip]):
            result = self.plugin.get_port(self.context, 1)
            for key in expected.keys():
                self.assertEqual(result[key], expected[key])

    def test_port_show_without_provider_subnet_ids(self):
        """Prove provider subnets ids are shown on the port object."""
        cfg.CONF.set_override('show_provider_subnet_ids', False, 'QUARK')
        self.addCleanup(
            cfg.CONF.clear_override, 'show_provider_subnet_ids', 'QUARK')

        ip = dict(id=1, address=netaddr.IPAddress("192.168.1.100").value,
                  address_readable="192.168.1.100", subnet_id="1",
                  network_id="1", version=4, address_type="fixed")
        port = dict(mac_address=int('AABBCCDDEEFF', 16), network_id="1",
                    tenant_id=self.context.tenant_id, device_id=2)
        expected = {'status': "ACTIVE",
                    'device_owner': None,
                    'mac_address': 'AA:BB:CC:DD:EE:FF',
                    'network_id': "1",
                    'tenant_id': self.context.tenant_id,
                    'admin_state_up': None,
                    'fixed_ips': [
                        {'subnet_id': '1', 'enabled': True,
                         'ip_address': '192.168.1.100'}
                    ],
                    'device_id': 2}
        with self._stubs(ports=port, addrs=[ip]):
            result = self.plugin.get_port(self.context, 1)
            for key in expected.keys():
                self.assertEqual(result[key], expected[key])


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

        with contextlib.nested(
            mock.patch("quark.db.api.port_find_by_ip_address")
        ) as (port_find_by_addr,):
            port_find_by_addr.return_value = addr_models
            yield

    def test_port_list_by_ip_address(self):
        ip = dict(id=1, address=netaddr.IPAddress("192.168.1.100").value,
                  address_readable="192.168.1.100", subnet_id=1, network_id=2,
                  version=4)
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
            with self.assertRaises(n_exc.NotAuthorized):
                self.plugin.get_ports(self.context, filters=filters,
                                      fields=None)

    def test_port_list_malformed_address_bad_request(self):
        with self._stubs(ports=[]):
            filters = {"ip_address": ["malformed-address-here"]}
            admin_ctx = self.context.elevated()
            with self.assertRaises(n_exc.BadRequest):
                self.plugin.get_ports(admin_ctx, filters=filters, fields=None)


class TestQuarkCreatePortFailure(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, port=None, network=None, addr=None, mac=None):
        if network:
            network["network_plugin"] = "BASE"
            network["ipam_strategy"] = "ANY"
        port_model = models.Port()
        port_model.update(port)
        port_models = port_model

        with contextlib.nested(
            mock.patch("quark.db.api.port_create"),
            mock.patch("quark.db.api.network_find"),
            mock.patch("quark.db.api.port_find"),
            mock.patch("quark.ipam.QuarkIpam.allocate_ip_address"),
            mock.patch("quark.ipam.QuarkIpam.allocate_mac_address"),
            mock.patch("quark.db.api.port_count_all"),
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
        network = dict(id=1, tenant_id=self.context.tenant_id)
        ip = dict()
        mac = dict(address="AA:BB:CC:DD:EE:FF")
        port_1 = dict(port=dict(mac_address="AA:BB:CC:DD:EE:00", network_id=1,
                                tenant_id=self.context.tenant_id, device_id=1,
                                name="Fake"))
        port_2 = dict(port=dict(mac_address="AA:BB:CC:DD:EE:11", network_id=1,
                                tenant_id=self.context.tenant_id, device_id=1,
                                name="Faker"))

        with self._stubs(port=port_1, network=network, addr=ip, mac=mac):
            with self.assertRaises(n_exc.BadRequest):
                self.plugin.create_port(self.context, port_1)
                self.plugin.create_port(self.context, port_2)


class TestQuarkCreatePortRM9305(test_quark_plugin.TestQuarkPlugin):
    def setUp(self):
        super(TestQuarkCreatePortRM9305, self).setUp()
        strategy = {"00000000-0000-0000-0000-000000000000":
                    {"bridge": "publicnet",
                     "subnets": {"4": "public_v4",
                                 "6": "public_v6"}},
                    "11111111-1111-1111-1111-111111111111":
                    {"bridge": "servicenet",
                     "subnets": {"4": "private_v4",
                                 "6": "private_v6"}}}
        strategy_json = json.dumps(strategy)
        quark_ports.STRATEGY = network_strategy.JSONStrategy(strategy_json)

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
            port_find.return_value = None
            alloc_ip.return_value = addr
            alloc_mac.return_value = mac
            port_count.return_value = 0
            yield port_create

    def test_RM9305_tenant_create_servicenet_port(self):
        network_id = "11111111-1111-1111-1111-111111111111"
        network = dict(id=network_id,
                       tenant_id="rackspace")
        ip = dict()
        mac = dict(address="AA:BB:CC:DD:EE:FF")
        port_1 = dict(port=dict(mac_address="AA:BB:CC:DD:EE:00",
                                network_id=network_id,
                                tenant_id=self.context.tenant_id, device_id=2,
                                segment_id="bar",
                                name="Fake"))

        with self._stubs(port=port_1, network=network, addr=ip, mac=mac):
            self.plugin.create_port(self.context, port_1)

    def test_RM9305_tenant_create_publicnet_port(self):
        network_id = "00000000-0000-0000-0000-000000000000"
        network = dict(id=network_id,
                       tenant_id="rackspace")
        ip = dict()
        mac = dict(address="AA:BB:CC:DD:EE:FF")
        port_1 = dict(port=dict(mac_address="AA:BB:CC:DD:EE:00",
                                network_id=network_id,
                                tenant_id=self.context.tenant_id, device_id=3,
                                segment_id="bar",
                                name="Fake"))

        with self._stubs(port=port_1, network=network, addr=ip, mac=mac):
            self.plugin.create_port(self.context, port_1)

    def test_RM9305_tenant_create_tenants_port(self):
        network_id = "foobar"
        network = dict(id=network_id,
                       tenant_id=self.context.tenant_id)
        ip = dict()
        mac = dict(address="AA:BB:CC:DD:EE:FF")
        port_1 = dict(port=dict(mac_address="AA:BB:CC:DD:EE:00",
                                network_id=network_id,
                                tenant_id=self.context.tenant_id, device_id=4,
                                name="Fake"))

        with self._stubs(port=port_1, network=network, addr=ip, mac=mac):
            self.plugin.create_port(self.context, port_1)

    def test_RM9305_tenant_create_other_tenants_port(self):
        network_id = "foobar"
        network = dict(id=network_id,
                       tenant_id="other_tenant")
        ip = dict()
        mac = dict(address="AA:BB:CC:DD:EE:FF")
        port_1 = dict(port=dict(mac_address="AA:BB:CC:DD:EE:00",
                                network_id=network_id,
                                tenant_id=self.context.tenant_id, device_id=5,
                                name="Fake"))

        with self._stubs(port=port_1, network=network, addr=ip, mac=mac):
            with self.assertRaises(n_exc.NotAuthorized):
                self.plugin.create_port(self.context, port_1)


class TestQuarkCreatePortsSameDevBadRequest(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, port=None, network=None, addr=None, mac=None,
               limit_checks=None, subnet=None):
        subnet_model = None

        if subnet:
            subnet_model = models.Subnet()
            subnet_model.update(subnet)

        if network:
            network["network_plugin"] = "BASE"
            network["ipam_strategy"] = "ANY"

        def _create_db_port(context, **kwargs):
            port_model = models.Port()
            port_model.update(kwargs)
            return port_model

        def _alloc_ip(context, new_ips, *args, **kwargs):
            ip_mod = models.IPAddress()
            ip_mod.update(addr)
            ip_mod.enabled_for_port = lambda x: True
            new_ips.extend([ip_mod])
            return mock.DEFAULT

        with contextlib.nested(
            mock.patch("quark.db.api.port_create"),
            mock.patch("quark.db.api.network_find"),
            mock.patch("quark.ipam.QuarkIpam.allocate_ip_address"),
            mock.patch("quark.ipam.QuarkIpam.allocate_mac_address"),
            mock.patch("quark.db.api.port_count_all"),
            mock.patch("neutron.quota.QuotaEngine.limit_check"),
            mock.patch("quark.db.api.subnet_find"),
        ) as (port_create, net_find, alloc_ip, alloc_mac, port_count,
              limit_check, subnet_find):
            port_create.side_effect = _create_db_port
            net_find.return_value = network
            alloc_ip.side_effect = _alloc_ip
            alloc_mac.return_value = mac
            if subnet:
                subnet_find.return_value = [subnet_model]
            port_count.return_value = 0
            if limit_checks:
                limit_check.side_effect = limit_checks
            yield port_create

    def test_create_port(self):
        network = dict(id=1, tenant_id=self.context.tenant_id)
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
        network = dict(id=1, tenant_id=self.context.tenant_id)
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
        network = dict(id=1, tenant_id=self.context.tenant_id)
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

    @mock.patch("quark.network_strategy.JSONStrategy.is_provider_network")
    def test_create_providernet_port_fixed_ip_not_authorized(self, is_parent):
        is_parent.return_value = True
        network = dict(id='1', tenant_id=self.context.tenant_id)
        subnet = dict(id=1, network_id=network["id"])
        mac = dict(address="AA:BB:CC:DD:EE:FF")
        ip = mock.MagicMock()
        ip.get = lambda x, *y: 1 if x == "subnet_id" else None
        ip.formatted = lambda: "192.168.10.45"
        ip.enabled_for_port = lambda x: True
        fixed_ips = [dict(subnet_id=1, enabled=True,
                     ip_address="192.168.10.45")]
        port = dict(port=dict(mac_address=mac["address"], network_id='1',
                              tenant_id=self.context.tenant_id, device_id=2,
                              fixed_ips=fixed_ips, ip_addresses=[ip],
                              segment_id="provider_segment"))

        with self._stubs(port=port["port"], network=network, addr=ip,
                         mac=mac, subnet=subnet):
            with self.assertRaises(n_exc.NotAuthorized):
                self.plugin.create_port(self.context, port)

    @mock.patch("quark.network_strategy.JSONStrategy.is_provider_network")
    def test_create_providernet_port_fixed_ip_wrong_segment(self, is_parent):
        is_parent.return_value = True
        network = dict(id='1', tenant_id=self.context.tenant_id)
        mac = dict(address="AA:BB:CC:DD:EE:FF")
        subnet = dict(id=1, network_id=network["id"])
        ip = mock.MagicMock()
        ip.get = lambda x, *y: 1 if x == "subnet_id" else None
        ip.formatted = lambda: "192.168.10.45"
        ip.enabled_for_port = lambda x: True
        fixed_ips = [dict(subnet_id=1, enabled=True,
                     ip_address="192.168.10.45")]
        port = dict(port=dict(mac_address=mac["address"], network_id='1',
                              tenant_id=self.context.tenant_id, device_id=2,
                              fixed_ips=fixed_ips, ip_addresses=[ip],
                              segment_id="provider_segment"))

        with self._stubs(port=port["port"], network=network, addr=ip,
                         mac=mac, subnet=subnet):
            with self.assertRaises(q_exc.AmbiguousNetworkId):
                self.plugin.create_port(self.context.elevated(), port)

    def test_create_port_fixed_ip_subnet_not_found(self):
        network = dict(id='1', tenant_id=self.context.tenant_id)
        mac = dict(address="AA:BB:CC:DD:EE:FF")
        ip = mock.MagicMock()
        ip.get = lambda x, *y: 1 if x == "subnet_id" else None
        ip.formatted = lambda: "192.168.10.45"
        ip.enabled_for_port = lambda x: True
        fixed_ips = [dict(subnet_id=1, enabled=True,
                     ip_address="192.168.10.45")]
        port = dict(port=dict(mac_address=mac["address"], network_id='1',
                              tenant_id=self.context.tenant_id, device_id=2,
                              fixed_ips=fixed_ips, ip_addresses=[ip],
                              segment_id="provider_segment"))

        with self._stubs(port=port["port"], network=network, addr=ip,
                         mac=mac):
            with self.assertRaises(n_exc.NotFound):
                self.plugin.create_port(self.context.elevated(), port)

    def test_create_port_fixed_ip_subnet_not_in_network(self):
        network = dict(id='1', tenant_id=self.context.tenant_id)
        mac = dict(address="AA:BB:CC:DD:EE:FF")
        subnet = dict(id=1, network_id='2')

        ip = mock.MagicMock()
        ip.get = lambda x, *y: 1 if x == "subnet_id" else None
        ip.formatted = lambda: "192.168.10.45"
        ip.enabled_for_port = lambda x: True
        fixed_ips = [dict(subnet_id=1, enabled=True,
                     ip_address="192.168.10.45")]
        port = dict(port=dict(mac_address=mac["address"], network_id='1',
                              tenant_id=self.context.tenant_id, device_id=2,
                              fixed_ips=fixed_ips, ip_addresses=[ip],
                              segment_id="provider_segment"))

        with self._stubs(port=port["port"], network=network, addr=ip,
                         mac=mac, subnet=subnet):
            with self.assertRaises(n_exc.InvalidInput):
                self.plugin.create_port(self.context.elevated(), port)

    def test_create_port_fixed_ips_bad_request(self):
        network = dict(id=1, tenant_id=self.context.tenant_id)
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
            with self.assertRaises(n_exc.BadRequest):
                self.plugin.create_port(self.context, port)

    def test_create_port_no_network_found(self):
        port = dict(port=dict(network_id=1, tenant_id=self.context.tenant_id,
                              device_id=2))
        with self._stubs(network=None, port=port["port"]):
            with self.assertRaises(n_exc.NetworkNotFound):
                self.plugin.create_port(self.context, port)

    def test_create_port_security_groups_raises(self, groups=[1]):
        network = dict(id=1, tenant_id=self.context.tenant_id)
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

        with contextlib.nested(
            mock.patch("quark.db.api.port_create"),
            mock.patch("quark.db.api.network_find"),
            mock.patch("quark.ipam.QuarkIpam.allocate_ip_address"),
            mock.patch("quark.ipam.QuarkIpam.allocate_mac_address"),
            mock.patch("quark.db.api.port_count_all"),
            mock.patch("neutron.quota.QuotaEngine.limit_check")
        ) as (port_create, net_find, alloc_ip, alloc_mac, port_count,
              limit_check):
            port_create.return_value = port_models
            net_find.return_value = network
            alloc_ip.return_value = addr
            alloc_mac.return_value = mac
            port_count.return_value = len(network["ports"])
            limit_check.side_effect = n_exc.OverQuota
            yield port_create

    def test_create_port_net_at_max(self):
        network = dict(id=1, ports=[models.Port()],
                       tenant_id=self.context.tenant_id)
        mac = dict(address="AA:BB:CC:DD:EE:FF")
        port_name = "foobar"
        ip = dict()
        port = dict(port=dict(mac_address=mac["address"], network_id=1,
                              tenant_id=self.context.tenant_id, device_id=2,
                              name=port_name))
        with self._stubs(port=port["port"], network=network, addr=ip, mac=mac):
            with self.assertRaises(n_exc.OverQuota):
                self.plugin.create_port(self.context, port)


class TestQuarkPortCreateFixedIpsQuota(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, network):
        network["network_plugin"] = "BASE"
        network["ipam_strategy"] = "ANY"
        with mock.patch("quark.db.api.network_find") as net_find:
            net_find.return_value = network
            yield

    def test_create_port_fixed_ips_over_quota(self):
        network = {"id": 1, "tenant_id": self.context.tenant_id}
        fixed_ips = [{"subnet_id": 1}, {"subnet_id": 1}, {"subnet_id": 1},
                     {"subnet_id": 1}, {"subnet_id": 1}, {"subnet_id": 1},
                     {"subnet_id": 1}]
        port = {"port": {"network_id": 1, "tenant_id": self.context.tenant_id,
                         "device_id": 2, "fixed_ips": fixed_ips}}
        with self._stubs(network=network):
            with self.assertRaises(n_exc.OverQuota):
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
        ) as (port_find, port_update, alloc_ip, dealloc_ip):
            port_find.return_value = port_model
            port_update.return_value = port_model
            if new_ips:
                alloc_ip.return_value = new_ips
            yield port_find, port_update, alloc_ip, dealloc_ip

    def test_update_port_not_found(self):
        with self._stubs(port=None):
            with self.assertRaises(n_exc.PortNotFound):
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
            with self.assertRaises(n_exc.BadRequest):
                self.plugin.update_port(self.context, 1, new_port)

    def test_update_port_fixed_ip_bad_request_malformed_address(self):
        with self._stubs(
            port=dict(id=1, name="myport", mac_address="0:0:0:0:0:1")
        ) as (port_find, port_update, alloc_ip, dealloc_ip):
            new_port = dict(port=dict(
                fixed_ips=[dict(subnet_id=1,
                                ip_address="malformed-address-here")]))
            with self.assertRaises(n_exc.BadRequest):
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
            with self.assertRaises(n_exc.BadRequest):
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
        new_addr_dict = {"address": netaddr.IPAddress("1.1.1.1"),
                         "address_readable": "1.1.1.1"}
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

    def test_update_port_goes_over_quota(self):
        fixed_ips = {"fixed_ips": [{"subnet_id": 1},
                                   {"subnet_id": 1},
                                   {"subnet_id": 1},
                                   {"subnet_id": 1},
                                   {"subnet_id": 1},
                                   {"subnet_id": 1},
                                   {"subnet_id": 1}]}
        with self._stubs(
            port=dict(id=1, name="myport", mac_address="0:0:0:0:0:1")
        ) as (port_find, port_update, alloc_ip, dealloc_ip):
            new_port = {"port": fixed_ips}
            with self.assertRaises(n_exc.OverQuota):
                self.plugin.update_port(self.context, 1, new_port)


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
                       ".is_provider_network"),
            mock.patch("quark.db.api.security_group_find"),
            mock.patch("quark.drivers.base.BaseDriver.update_port")
        ) as (port_find, port_update, alloc_ip, dealloc_ip, limit_check,
              net_strat, sg_find, driver_port_update):
            port_find.return_value = port_model

            def _port_update(context, port_db, **kwargs):
                return port_db.update(kwargs)
            port_update.side_effect = _port_update
            if new_ips:
                alloc_ip.return_value = new_ips
            net_strat.return_value = parent_net
            sg_find.return_value = sg_mod
            yield (port_find, port_update, alloc_ip, dealloc_ip, sg_find,
                   driver_port_update)

    def test_update_port_security_groups(self):
        with self._stubs(
            port=dict(id=1, device_id="device"), parent_net=True
        ) as (port_find, port_update, alloc_ip, dealloc_ip, sg_find,
              driver_port_update):
            new_port = dict(port=dict(name="ourport",
                                      security_groups=[1]))
            port = self.plugin.update_port(self.context, 1, new_port)
            port_update.assert_called_once_with(
                self.context,
                port_find(),
                name="ourport",
                security_groups=[sg_find()])
            self.assertEqual(sg_find()["id"], port["security_groups"][0])

    def test_update_port_empty_list_security_groups(self):
        port_dict = {"id": 1, "mac_address": "AA:BB:CC:DD:EE:FF",
                     "device_id": 2, "backend_key": 3}
        with self._stubs(
            port=port_dict, parent_net=True
        ) as (port_find, port_update, alloc_ip, dealloc_ip, sg_find,
              driver_port_update):
            new_port = dict(port=dict(name="ourport",
                                      security_groups=[]))
            port = self.plugin.update_port(self.context, 1, new_port)
            self.assertEqual(port["security_groups"], [])
            port_update.assert_called_once_with(
                self.context,
                port_find(),
                name="ourport",
                security_groups=[])
            driver_port_update.assert_called_once_with(
                self.context, port_id=port_dict["backend_key"],
                mac_address=port_dict["mac_address"],
                device_id=port_dict["device_id"],
                security_groups=[],
                base_net_driver=registry.DRIVER_REGISTRY.get_driver('BASE'))

    def test_update_port_no_security_groups(self):
        port_dict = {"id": 1, "mac_address": "AA:BB:CC:DD:EE:FF",
                     "device_id": 2, "backend_key": 3}
        with self._stubs(
            port=port_dict, parent_net=True
        ) as (port_find, port_update, alloc_ip, dealloc_ip, sg_find,
              driver_port_update):
            new_port = dict(port=dict(name="ourport"))
            self.plugin.update_port(self.context, 1, new_port)
            driver_port_update.assert_called_once_with(
                self.context, port_id=port_dict["backend_key"],
                mac_address=port_dict["mac_address"],
                device_id=port_dict["device_id"],
                base_net_driver=registry.DRIVER_REGISTRY.get_driver('BASE'))

    def test_update_port_security_groups_no_device_id_raises(self):
        with self._stubs(
            port=dict(id=1), parent_net=True
        ) as (port_find, port_update, alloc_ip, dealloc_ip, sg_find,
              driver_port_update):
            new_port = dict(port=dict(name="ourport",
                                      security_groups=[1]))
            with self.assertRaises(q_exc.SecurityGroupsRequireDevice):
                self.plugin.update_port(self.context, 1, new_port)


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
        new_addr_dict = {"address": netaddr.IPAddress('1.1.1.1'),
                         "address_readable": "1.1.1.1"}
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


class TestQuarkCreatePortOnSharedNetworks(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, port=None, network=None, addr=None, mac=None):
        self.strategy = {"public_network":
                         {"bridge": "xenbr0",
                          "subnets": {"4": "public_v4",
                                      "6": "public_v6"}}}
        strategy_json = json.dumps(self.strategy)
        quark_ports.STRATEGY = network_strategy.JSONStrategy(strategy_json)

        if network:
            network["network_plugin"] = "BASE"
            network["ipam_strategy"] = "ANY"
        port_model = models.Port()
        port_model.update(port)
        port_models = port_model

        with contextlib.nested(
            mock.patch("quark.db.api.port_create"),
            mock.patch("quark.db.api.network_find"),
            mock.patch("quark.ipam.QuarkIpam.allocate_ip_address"),
            mock.patch("quark.ipam.QuarkIpam.allocate_mac_address"),
            mock.patch("neutron.quota.QuotaEngine.limit_check")
        ) as (port_create, net_find, alloc_ip, alloc_mac, limit_check):
            port_create.return_value = port_models
            net_find.return_value = network
            alloc_ip.return_value = addr
            alloc_mac.return_value = mac
            yield port_create

    def test_create_port_shared_net_no_quota_check(self):
        network = dict(id=1, ports=[models.Port()],
                       tenant_id=self.context.tenant_id)
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
        network = dict(id=1, ports=[models.Port()],
                       tenant_id=self.context.tenant_id)
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

        with contextlib.nested(
            mock.patch("quark.db.api.port_find"),
            mock.patch("quark.ipam.QuarkIpam.deallocate_ips_by_port"),
            mock.patch("quark.ipam.QuarkIpam.deallocate_mac_address"),
            mock.patch("quark.db.api.port_delete"),
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
            driver_port_del.assert_called_with(
                self.context, "foo", mac_address=port["port"]["mac_address"],
                device_id=port["port"]["device_id"],
                base_net_driver=registry.DRIVER_REGISTRY.get_driver("BASE"))

    def test_port_delete_port_not_found_fails(self):
        with self._stubs(port=None) as (db_port_del, driver_port_del):
            with self.assertRaises(n_exc.PortNotFound):
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
        ip = dict(id=1, address=netaddr.IPAddress("192.168.1.100"),
                  address_readable="192.168.1.100", subnet_id=1, network_id=2,
                  version=4)
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
        ip = dict(id=1, address=netaddr.IPAddress("192.168.1.100"),
                  address_readable="192.168.1.100", subnet_id=1, network_id=2,
                  version=4)
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
        ip = dict(id=1, address=netaddr.IPAddress("192.168.1.100"),
                  address_readable="192.168.1.100", subnet_id=1, network_id=2,
                  version=4)
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
            with self.assertRaises(n_exc.PortNotFound):
                self.plugin.diagnose_port(self.context.elevated(), 1, [])

    def test_port_diagnose_not_authorized(self):
        with self._stubs(port=None):
            with self.assertRaises(n_exc.NotAuthorized):
                self.plugin.diagnose_port(self.context, 1, [])


class TestPortDriverSelection(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, network=None, addr=None, mac=None,
               compat_map=None, driver_res=None, ipam="FOO"):
        network["ipam_strategy"] = "FOO"

        # Response from the backend driver
        self.expected_bridge = "backend-drivers-bridge"
        if driver_res is None:
            driver_res = {"uuid": 1, "bridge": self.expected_bridge}

        # Mock out the driver registry
        foo_driver = mock.Mock()
        foo_driver.create_port.return_value = driver_res
        foo_driver.select_ipam_strategy.return_value = "FOO"
        bar_driver = mock.Mock()
        bar_driver.create_port.return_value = driver_res
        bar_driver.select_ipam_strategy.return_value = "BAR"
        drivers = {"FOO": foo_driver,
                   "BAR": bar_driver}
        compat_map = compat_map or {}

        # Mock out the IPAM registry
        foo_ipam = mock.Mock()
        foo_ipam.allocate_ip_address.return_value = addr
        foo_ipam.allocate_mac_address.return_value = mac
        bar_ipam = mock.Mock()
        bar_ipam.allocate_ip_address.return_value = addr
        bar_ipam.allocate_mac_address.return_value = mac
        ipam = {"FOO": foo_ipam, "BAR": bar_ipam}

        with contextlib.nested(
            mock.patch("quark.db.api.port_create"),
            mock.patch("quark.db.api.network_find"),
            mock.patch("oslo_utils.uuidutils.generate_uuid"),
            mock.patch("quark.plugin_views._make_port_dict"),
            mock.patch("quark.db.api.port_count_all"),
            mock.patch("neutron.quota.QuotaEngine.limit_check"),
            mock.patch("quark.plugin_modules.ports.registry."
                       "DRIVER_REGISTRY.drivers",
                       new_callable=mock.PropertyMock(return_value=drivers)),
            mock.patch("quark.plugin_modules.ports.registry."
                       "DRIVER_REGISTRY.port_driver_compat_map",
                       new_callable=mock.PropertyMock(
                           return_value=compat_map)),
            mock.patch("quark.plugin_modules.ports.ipam."
                       "IPAM_REGISTRY.strategies",
                       new_callable=mock.PropertyMock(return_value=ipam))
        ) as (port_create, net_find, gen_uuid, make_port,
              port_count, limit_check, _, _, _):
            net_find.return_value = network
            gen_uuid.return_value = 1
            port_count.return_value = 0
            yield (port_create, ipam, net_find)

    def test_create_port_with_bad_network_plugin_fails(self):
        network_dict = dict(id=1, tenant_id=self.context.tenant_id)
        port_name = "foobar"
        mac = dict(address="AA:BB:CC:DD:EE:FF")
        ip = dict()
        port = dict(port=dict(mac_address=mac["address"], network_id=1,
                              tenant_id=self.context.tenant_id, device_id=2,
                              name=port_name))
        network = models.Network()
        network.update(network_dict)
        network["network_plugin"] = "FAIL"
        port_model = models.Port()
        port_model.update(port)
        port_models = port_model

        with self._stubs(network=network, addr=ip,
                         mac=mac) as (port_create, ipam, net_find):
            port_create.return_value = port_models

            exc = "Driver FAIL is not registered."
            with self.assertRaisesRegexp(n_exc.BadRequest, exc):
                self.plugin.create_port(self.context, port)

    def test_create_port_with_bad_port_network_plugin_fails(self):
        network_dict = dict(id=1, tenant_id=self.context.tenant_id)
        port_name = "foobar"
        mac = dict(address="AA:BB:CC:DD:EE:FF")
        ip = dict()
        port = dict(port=dict(mac_address=mac["address"], network_id=1,
                              tenant_id=self.context.tenant_id, device_id=2,
                              name=port_name, network_plugin="FAIL"))
        network = models.Network()
        network.update(network_dict)
        network["network_plugin"] = "FOO"
        port_model = models.Port()
        port_model.update(port)
        port_models = port_model

        with self._stubs(network=network, addr=ip,
                         mac=mac) as (port_create, ipam, net_find):
            port_create.return_value = port_models

            exc = "Driver FAIL is not registered."
            admin_ctx = self.context.elevated()
            with self.assertRaisesRegexp(n_exc.BadRequest, exc):
                self.plugin.create_port(admin_ctx, port)

    def test_create_port_with_incompatable_port_network_plugin_fails(self):
        network_dict = dict(id=1, tenant_id=self.context.tenant_id)
        port_name = "foobar"
        mac = dict(address="AA:BB:CC:DD:EE:FF")
        ip = dict()
        port = dict(port=dict(mac_address=mac["address"], network_id=1,
                              tenant_id=self.context.tenant_id, device_id=2,
                              name=port_name, network_plugin="BAR"))
        network = models.Network()
        network.update(network_dict)
        network["network_plugin"] = "FOO"
        port_model = models.Port()
        port_model.update(port)
        port_models = port_model

        with self._stubs(network=network, addr=ip,
                         mac=mac) as (port_create, ipam, net_find):
            port_create.return_value = port_models

            exc = ("Port driver BAR not allowed for underlying network "
                   "driver FOO.")
            admin_ctx = self.context.elevated()
            with self.assertRaisesRegexp(n_exc.BadRequest, exc):
                self.plugin.create_port(admin_ctx, port)

    def test_create_port_with_no_port_network_plugin(self):
        network = dict(id=1, tenant_id=self.context.tenant_id,
                       network_plugin="FOO")
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
                         mac=mac) as (port_create, ipam, net_find):
            self.plugin.create_port(admin_ctx, port_create_dict)

            ipam["BAR"].allocate_mac_address.assert_not_called()
            ipam["BAR"].allocate_ip_address.assert_not_called()

            ipam["FOO"].allocate_ip_address.assert_called_once_with(
                admin_ctx, [], network["id"], 1,
                cfg.CONF.QUARK.ipam_reuse_after,
                segment_id=None, mac_address=mac)

            ipam["FOO"].allocate_mac_address.assert_called_once_with(
                admin_ctx, network["id"], 1,
                cfg.CONF.QUARK.ipam_reuse_after,
                mac_address=expected_mac, use_forbidden_mac_range=False)

            port_create.assert_called_once_with(
                admin_ctx, bridge=self.expected_bridge, uuid=1, name="foobar",
                admin_state_up=expected_admin_state, network_id=1,
                tenant_id="fake", id=1, device_owner=expected_device_owner,
                mac_address=mac["address"], device_id=2, backend_key=1,
                security_groups=[], addresses=[], instance_node_id='',
                network_plugin="FOO")

    def test_create_port_with_port_network_plugin(self):
        network = dict(id=1, tenant_id=self.context.tenant_id,
                       network_plugin="FOO")
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
        expected_network_plugin = "FOO"

        port_create_dict = {}
        port_create_dict["port"] = port["port"].copy()
        port_create_dict["port"]["mac_address"] = expected_mac
        port_create_dict["port"]["device_owner"] = expected_device_owner
        port_create_dict["port"]["bridge"] = expected_bridge
        port_create_dict["port"]["admin_state_up"] = expected_admin_state
        port_create_dict["port"]["network_plugin"] = expected_network_plugin

        admin_ctx = self.context.elevated()
        with self._stubs(network=network, addr=ip,
                         mac=mac) as (port_create, ipam, net_find):
            self.plugin.create_port(admin_ctx, port_create_dict)

            ipam["BAR"].allocate_mac_address.assert_not_called()
            ipam["BAR"].allocate_ip_address.assert_not_called()

            ipam["FOO"].allocate_ip_address.assert_called_once_with(
                admin_ctx, [], network["id"], 1,
                cfg.CONF.QUARK.ipam_reuse_after,
                segment_id=None, mac_address=mac)

            ipam["FOO"].allocate_mac_address.assert_called_once_with(
                admin_ctx, network["id"], 1,
                cfg.CONF.QUARK.ipam_reuse_after,
                mac_address=expected_mac, use_forbidden_mac_range=False)

            port_create.assert_called_once_with(
                admin_ctx, bridge=self.expected_bridge, uuid=1, name="foobar",
                admin_state_up=expected_admin_state, network_id=1,
                tenant_id="fake", id=1, device_owner=expected_device_owner,
                mac_address=mac["address"], device_id=2, backend_key=1,
                security_groups=[], addresses=[], instance_node_id='',
                network_plugin=expected_network_plugin)

    def test_create_port_with_compatible_port_network_plugin(self):
        network = dict(id=1, tenant_id=self.context.tenant_id,
                       network_plugin="FOO")
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
        expected_network_plugin = "BAR"

        port_create_dict = {}
        port_create_dict["port"] = port["port"].copy()
        port_create_dict["port"]["mac_address"] = expected_mac
        port_create_dict["port"]["device_owner"] = expected_device_owner
        port_create_dict["port"]["bridge"] = expected_bridge
        port_create_dict["port"]["admin_state_up"] = expected_admin_state
        port_create_dict["port"]["network_plugin"] = expected_network_plugin

        compat_map = {"BAR": ["FOO"]}
        admin_ctx = self.context.elevated()
        with self._stubs(network=network, addr=ip, mac=mac,
                         compat_map=compat_map) as (port_create, ipam,
                                                    net_find):
            self.plugin.create_port(admin_ctx, port_create_dict)

            ipam["FOO"].allocate_mac_address.assert_not_called()
            ipam["FOO"].allocate_ip_address.assert_not_called()

            ipam["BAR"].allocate_ip_address.assert_called_once_with(
                admin_ctx, [], network["id"], 1,
                cfg.CONF.QUARK.ipam_reuse_after,
                segment_id=None, mac_address=mac)

            ipam["BAR"].allocate_mac_address.assert_called_once_with(
                admin_ctx, network["id"], 1,
                cfg.CONF.QUARK.ipam_reuse_after,
                mac_address=expected_mac, use_forbidden_mac_range=False)

            port_create.assert_called_once_with(
                admin_ctx, bridge=self.expected_bridge, uuid=1, name="foobar",
                admin_state_up=expected_admin_state, network_id=1,
                tenant_id="fake", id=1, device_owner=expected_device_owner,
                mac_address=mac["address"], device_id=2, backend_key=1,
                security_groups=[], addresses=[], instance_node_id='',
                network_plugin=expected_network_plugin)

    def test_create_port_ipam_selection(self):
        network = dict(id=1, tenant_id=self.context.tenant_id,
                       network_plugin="FOO")
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
                         mac=mac) as (port_create, ipam, net_find):
            self.plugin.create_port(admin_ctx, port_create_dict)

            ipam["BAR"].allocate_mac_address.assert_not_called()
            ipam["BAR"].allocate_ip_address.assert_not_called()

            ipam["FOO"].allocate_ip_address.assert_called_once_with(
                admin_ctx, [], network["id"], 1,
                cfg.CONF.QUARK.ipam_reuse_after,
                segment_id=None, mac_address=mac)

            ipam["FOO"].allocate_mac_address.assert_called_once_with(
                admin_ctx, network["id"], 1,
                cfg.CONF.QUARK.ipam_reuse_after,
                mac_address=expected_mac, use_forbidden_mac_range=False)

            port_create.assert_called_once_with(
                admin_ctx, bridge=self.expected_bridge, uuid=1, name="foobar",
                admin_state_up=expected_admin_state, network_id=1,
                tenant_id="fake", id=1, device_owner=expected_device_owner,
                mac_address=mac["address"], device_id=2, backend_key=1,
                security_groups=[], addresses=[], instance_node_id='',
                network_plugin="FOO")

    def test_create_port_ipam_selection_override_by_driver(self):
        network = dict(id=1, tenant_id=self.context.tenant_id,
                       network_plugin="BAR")
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
                         mac=mac, ipam="BAR") as (port_create, ipam, net_find):
            self.plugin.create_port(admin_ctx, port_create_dict)

            ipam["FOO"].allocate_mac_address.assert_not_called()
            ipam["FOO"].allocate_ip_address.assert_not_called()

            ipam["BAR"].allocate_ip_address.assert_called_once_with(
                admin_ctx, [], network["id"], 1,
                cfg.CONF.QUARK.ipam_reuse_after,
                segment_id=None, mac_address=mac)

            ipam["BAR"].allocate_mac_address.assert_called_once_with(
                admin_ctx, network["id"], 1,
                cfg.CONF.QUARK.ipam_reuse_after,
                mac_address=expected_mac, use_forbidden_mac_range=False)

            port_create.assert_called_once_with(
                admin_ctx, bridge=self.expected_bridge, uuid=1, name="foobar",
                admin_state_up=expected_admin_state, network_id=1,
                tenant_id="fake", id=1, device_owner=expected_device_owner,
                mac_address=mac["address"], device_id=2, backend_key=1,
                security_groups=[], addresses=[], instance_node_id='',
                network_plugin="BAR")

    def test_create_port_network_plugin_response_no_uuid_raises(self):
        network_dict = dict(id=1, tenant_id=self.context.tenant_id)
        port_name = "foobar"
        mac = dict(address="AA:BB:CC:DD:EE:FF")
        ip = dict()
        port = dict(port=dict(mac_address=mac["address"], network_id=1,
                              tenant_id=self.context.tenant_id, device_id=2,
                              name=port_name))
        network = models.Network()
        network.update(network_dict)
        network["network_plugin"] = "FOO"
        port_model = models.Port()
        port_model.update(port)
        port_models = port_model

        with self._stubs(network=network, addr=ip,
                         mac=mac, driver_res={}) as (port_create,
                                                     alloc_mac,
                                                     net_find):
            port_create.return_value = port_models

            exc = "uuid"
            with self.assertRaisesRegexp(KeyError, exc):
                self.plugin.create_port(self.context, port)

    def test_create_port_network_plugin_response_is_filtered(self):
        network = dict(id=1, tenant_id=self.context.tenant_id,
                       network_plugin="FOO")
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

        driver_res = {
            "uuid": 5,
            "vlan_id": 50,
            "tags": [123, {"foo": "bar"}],
            "id": "fail",
            "randomkey": None
        }

        admin_ctx = self.context.elevated()
        with self._stubs(network=network, addr=ip,
                         mac=mac, driver_res=driver_res) as (port_create,
                                                             ipam,
                                                             net_find):
            self.plugin.create_port(admin_ctx, port_create_dict)

            ipam["BAR"].allocate_mac_address.assert_not_called()
            ipam["BAR"].allocate_ip_address.assert_not_called()

            ipam["FOO"].allocate_ip_address.assert_called_once_with(
                admin_ctx, [], network["id"], 1,
                cfg.CONF.QUARK.ipam_reuse_after,
                segment_id=None, mac_address=mac)

            ipam["FOO"].allocate_mac_address.assert_called_once_with(
                admin_ctx, network["id"], 1,
                cfg.CONF.QUARK.ipam_reuse_after,
                mac_address=expected_mac, use_forbidden_mac_range=False)

            port_create.assert_called_once_with(
                admin_ctx, bridge=expected_bridge, uuid=5, name="foobar",
                admin_state_up=expected_admin_state, network_id=1,
                tenant_id="fake", id=1, device_owner=expected_device_owner,
                mac_address=mac["address"], device_id=2, backend_key=5,
                security_groups=[], addresses=[], vlan_id=50,
                network_plugin=network["network_plugin"], instance_node_id='')


class TestQuarkPortCreateFiltering(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, network=None, addr=None, mac=None):
        network["network_plugin"] = "BASE"
        network["ipam_strategy"] = "ANY"

        with contextlib.nested(
            mock.patch("quark.db.api.port_create"),
            mock.patch("quark.db.api.network_find"),
            mock.patch("quark.ipam.QuarkIpam.allocate_ip_address"),
            mock.patch("quark.ipam.QuarkIpam.allocate_mac_address"),
            mock.patch("oslo_utils.uuidutils.generate_uuid"),
            mock.patch("quark.plugin_views._make_port_dict"),
            mock.patch("quark.db.api.port_count_all"),
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
        network = dict(id=1, tenant_id=self.context.tenant_id)
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
        port_create_dict["port"]["network_plugin"] = "ignored"

        with self._stubs(network=network, addr=ip,
                         mac=mac) as (port_create, alloc_mac, net_find):
            self.plugin.create_port(self.context, port_create_dict)
            alloc_mac.assert_called_once_with(
                self.context, network["id"], 1,
                cfg.CONF.QUARK.ipam_reuse_after,
                mac_address=None, use_forbidden_mac_range=False)
            port_create.assert_called_once_with(
                self.context, addresses=[], network_id=network["id"],
                tenant_id="fake", uuid=1, name="foobar",
                mac_address=alloc_mac()["address"], backend_key=1, id=1,
                security_groups=[], network_plugin='BASE',
                device_id=2, instance_node_id='')

    def test_create_port_attribute_filtering_admin(self):
        network = dict(id=1, tenant_id=self.context.tenant_id)
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
        expected_network_plugin = "BASE"

        port_create_dict = {}
        port_create_dict["port"] = port["port"].copy()
        port_create_dict["port"]["mac_address"] = expected_mac
        port_create_dict["port"]["device_owner"] = expected_device_owner
        port_create_dict["port"]["bridge"] = expected_bridge
        port_create_dict["port"]["admin_state_up"] = expected_admin_state
        port_create_dict["port"]["network_plugin"] = expected_network_plugin

        admin_ctx = self.context.elevated()
        with self._stubs(network=network, addr=ip,
                         mac=mac) as (port_create, alloc_mac, net_find):
            self.plugin.create_port(admin_ctx, port_create_dict)

            alloc_mac.assert_called_once_with(
                admin_ctx, network["id"], 1,
                cfg.CONF.QUARK.ipam_reuse_after,
                mac_address=expected_mac, use_forbidden_mac_range=False)

            port_create.assert_called_once_with(
                admin_ctx, bridge=expected_bridge, uuid=1, name="foobar",
                admin_state_up=expected_admin_state, network_id=1,
                tenant_id="fake", id=1, device_owner=expected_device_owner,
                mac_address=mac["address"], device_id=2, backend_key=1,
                security_groups=[], addresses=[],
                network_plugin=expected_network_plugin, instance_node_id='')


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
            "network_id": 10, "backend_key": 1234, "name": "new_name",
            "network_plugin": "BASE"}

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
            "network_id": 10, "backend_key": 1234, "name": "new_name",
            "network_plugin": "BASE"}

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


class TestQuarkPortCreateAsAdvancedService(test_quark_plugin.TestQuarkPlugin):

    @contextlib.contextmanager
    def _stubs(self, port=None, network=None, addr=None, mac=None):
        if network:
            network["network_plugin"] = "BASE"
            network["ipam_strategy"] = "ANY"
        port_model = models.Port()
        port_model.update(port['port'])
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
            port_find.return_value = None
            alloc_ip.return_value = addr
            alloc_mac.return_value = mac
            port_count.return_value = 0
            yield port_create

    def test_advanced_service_create_port_other_tenant_network(self):
        """NCP-1819 - Advanced service can create port on any network

        Tests when an advanced service creating a port on another tenant's
        network does not fail AND the tenant_id is that of the context's.
        """
        self.context.is_advsvc = True
        network_id = "foobar"
        network = dict(id=network_id,
                       tenant_id="other_tenant")
        ip = dict()
        mac = dict(address="AA:BB:CC:DD:EE:FF")
        port_1 = dict(port=dict(mac_address="AA:BB:CC:DD:EE:00",
                                network_id=network_id,
                                tenant_id=self.context.tenant_id, device_id=5,
                                name="Fake"))

        with self._stubs(port=port_1, network=network, addr=ip, mac=mac):
            port = self.plugin.create_port(self.context, port_1)
            self.assertEqual(self.context.tenant_id, port['tenant_id'])

    def test_advsvc_can_create_port_with_another_tenant_id(self):
        """NCP-1819 - Advanced Service can create port on another tenant's net

        Tests that an advanced service can create a port on another tenant's
        network.
        """
        another_tenant_id = 'im-another-tenant'
        self.context.is_advsvc = True
        network_id = "foobar"
        network = dict(id=network_id,
                       tenant_id="other_tenant")
        ip = dict()
        mac = dict(address="AA:BB:CC:DD:EE:FF")
        port_1 = dict(port=dict(mac_address="AA:BB:CC:DD:EE:00",
                                network_id=network_id,
                                tenant_id=another_tenant_id, device_id=5,
                                name="Fake"))

        with self._stubs(port=port_1, network=network, addr=ip, mac=mac):
            port = self.plugin.create_port(self.context, port_1)
            self.assertEqual(another_tenant_id, port['tenant_id'])

    def test_non_advsvc_cannot_create_port_another_network(self):
        """NCP-1819 - Normal tenant port create should fail another's network

        Tests that a normal tenant creating a port on another tenant's network
        should not be allowed and throws an exception.
        """
        normal_tenant_id = "other_tenant"
        network_id = "foobar"
        network = dict(id=network_id,
                       tenant_id=normal_tenant_id)
        ip = dict()
        mac = dict(address="AA:BB:CC:DD:EE:FF")
        port_1 = dict(port=dict(mac_address="AA:BB:CC:DD:EE:00",
                                network_id=network_id,
                                tenant_id=normal_tenant_id, device_id=5,
                                name="Fake"))

        with self._stubs(port=port_1, network=network, addr=ip, mac=mac):
            with self.assertRaises(n_exc.NotAuthorized):
                self.plugin.create_port(self.context, port_1)
