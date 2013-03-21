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

import uuid

import contextlib
import mock
import netaddr
from oslo.config import cfg
from quantum.common import exceptions
from quantum import context
from quantum.db import api as db_api

from quark.db import models
import quark.plugin

from quark.tests import test_base


class TestQuarkPlugin(test_base.TestBase):
    def setUp(self):
        cfg.CONF.set_override('sql_connection', 'sqlite://', 'DATABASE')
        db_api.configure_db()
        self.context = context.get_admin_context()
        self.plugin = quark.plugin.Plugin()

    def _create_network(self, name='test'):
        network = {'network': {'name': name}}
        return self.plugin.create_network(self.context, network)

    def _create_subnet(self, network_id, cidr='192.168.10.1/24'):
        subnet = {'subnet': {'cidr': cidr,
                             'network_id': network_id}}
        return self.plugin.create_subnet(self.context, subnet)

    def _create_mac_address_range(self, cidr='01:23:45/24'):
        mac_range = {'mac_address_range': {'cidr': cidr}}
        return self.plugin.create_mac_address_range(self.context, mac_range)

    def _create_port(self, network_id, device_id=''):
        port = {'port': {'network_id': network_id,
                         'device_id': device_id}}
        return self.plugin.create_port(self.context, port)

    def tearDown(self):
        db_api.clear_db()


class TestQuarkGetSubnets(TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, subnets=None, routes=None):
        route_models = []
        for route in routes:
            r = models.Route()
            r.update(route)
            route_models.append(r)

        if isinstance(subnets, list):
            subnet_models = []
            for subnet in subnets:
                s_dict = subnet.copy()
                s_dict["routes"] = route_models
                s = models.Subnet()
                s.update(s_dict)
                subnet_models.append(s)
        else:
            mod = models.Subnet()
            mod.update(subnets)
            mod["routes"] = route_models
            subnet_models = mod

        with mock.patch("quark.db.api.subnet_find") as subnet_find:
            subnet_find.return_value = subnet_models
            yield

    def test_subnets_list(self):
        subnet_id = str(uuid.uuid4())
        route = dict(id=1, cidr="192.168.0.0/24", gateway="192.168.0.1",
                     subnet_id=subnet_id)

        subnet = dict(id=subnet_id, network_id=1, name=subnet_id,
                      tenant_id=self.context.tenant_id, ip_version=4,
                      cidr="172.16.0.0/24", gateway_ip="0.0.0.0",
                      allocation_pools=[], dns_nameservers=[],
                      enable_dhcp=True)

        with self._stubs(subnets=[subnet], routes=[route]):
            res = self.plugin.get_subnets(self.context, {}, {})

            # Compare routes separately
            routes = res[0].pop("routes")
            for key in subnet.keys():
                self.assertEqual(res[0][key], subnet[key])
            for key in route.keys():
                self.assertEqual(routes[0][key], route[key])

    def test_subnet_show(self):
        subnet_id = str(uuid.uuid4())
        route = dict(id=1, cidr="192.168.0.0/24", gateway="192.168.0.1",
                     subnet_id=subnet_id)

        subnet = dict(id=subnet_id, network_id=1, name=subnet_id,
                      tenant_id=self.context.tenant_id, ip_version=4,
                      cidr="172.16.0.0/24", gateway_ip="0.0.0.0",
                      allocation_pools=[], dns_nameservers=[],
                      enable_dhcp=True)

        with self._stubs(subnets=subnet, routes=[route]):
            res = self.plugin.get_subnet(self.context, subnet_id)

            # Compare routes separately
            routes = res.pop("routes")
            for key in subnet.keys():
                self.assertEqual(res[key], subnet[key])
            for key in route.keys():
                self.assertEqual(routes[0][key], route[key])


class TestQuarkCreateSubnet(TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, subnet=None, network=None):
        subnet_mod = models.Subnet()
        subnet_mod.update(subnet)
        with contextlib.nested(
            mock.patch("quark.db.api.subnet_create"),
            mock.patch("quark.db.api.network_find"),
        ) as (subnet_create, net_find):
            subnet_create.return_value = subnet_mod
            net_find.return_value = network
            yield

    def test_create_subnet(self):
        subnet = dict(
            subnet=dict(network_id=1,
                        tenant_id=self.context.tenant_id, ip_version=4,
                        cidr="172.16.0.0/24", gateway_ip="0.0.0.0",
                        allocation_pools=[], dns_nameservers=[],
                        enable_dhcp=None))
        network = dict(network_id=1)
        with self._stubs(subnet=subnet["subnet"], network=network):
            res = self.plugin.create_subnet(self.context, subnet)
            for key in subnet["subnet"].keys():
                print key
                self.assertEqual(res[key], subnet["subnet"][key])

    def test_create_subnet_no_network_fails(self):
        subnet = dict(subnet=dict(network_id=1))
        with self._stubs(subnet=dict(), network=None):
            with self.assertRaises(exceptions.NetworkNotFound):
                self.plugin.create_subnet(self.context, subnet)


class TestIpAddresses(TestQuarkPlugin):
    # TODO(amir): add test to check filter for tenant_id

    def test_create_ip_address_network_and_device(self):
        network_id = self._create_network()['id']
        subnet = self._create_subnet(network_id)
        self._create_mac_address_range()
        device_id = 'onetwothree'
        port_id = self._create_port(network_id, device_id)['id']

        ip_address = {'ip_address': {'network_id': network_id,
                                     'device_id': device_id}}
        response = self.plugin.create_ip_address(self.context,
                                                 ip_address)

        self.assertIsNotNone(response['id'])
        self.assertEqual(response['network_id'], network_id)
        self.assertIn(netaddr.IPAddress(response['address']),
                      netaddr.IPNetwork(subnet['cidr']))
        self.assertEqual(response['port_ids'], [port_id])
        self.assertEqual(response['subnet_id'], subnet['id'])

    def test_create_ip_address_invalid_network_and_device(self):
        with self.assertRaises(exceptions.PortNotFound):
            ip_address = {'ip_address': {'network_id': 'fake',
                                         'device_id': 'fake'}}
            self.plugin.create_ip_address(self.context, ip_address)

    def test_create_ip_address_with_port(self):
        network_id = self._create_network()['id']
        subnet = self._create_subnet(network_id)
        self._create_mac_address_range()
        port_id = self._create_port(network_id)['id']

        ip_address = {'ip_address': {'port_id': port_id}}
        response = self.plugin.create_ip_address(self.context,
                                                 ip_address)

        self.assertIsNotNone(response['id'])
        self.assertEqual(response['network_id'], network_id)
        self.assertIn(netaddr.IPAddress(response['address']),
                      netaddr.IPNetwork(subnet['cidr']))
        self.assertEqual(response['port_ids'], [port_id])
        self.assertEqual(response['subnet_id'], subnet['id'])

    def test_create_ip_address_invalid_port(self):
        with self.assertRaises(exceptions.PortNotFound):
            ip_address = {'ip_address': {'port_id': 'fake'}}
            self.plugin.create_ip_address(self.context, ip_address)

    def test_create_ip_address_no_fields(self):
        with self.assertRaises(exceptions.PortNotFound):
            ip_address = {'ip_address': {}}
            self.plugin.create_ip_address(self.context, ip_address)

    def test_create_ip_address_no_device(self):
        network_id = self._create_network()['id']
        with self.assertRaises(exceptions.PortNotFound):
            ip_address = {'ip_address': {'network_id': network_id}}
            self.plugin.create_ip_address(self.context, ip_address)

    def test_create_ip_address_no_network(self):
        network_id = self._create_network()['id']
        self._create_subnet(network_id)['id']
        self._create_mac_address_range()
        device_id = 'onetwothree'
        self._create_port(network_id, device_id=device_id)['id']

        with self.assertRaises(exceptions.PortNotFound):
            ip_address = {'ip_address': {'device_id': device_id}}
            self.plugin.create_ip_address(self.context, ip_address)

    def test_create_ip_address_ipv4(self):
        network_id = self._create_network()['id']
        subnet_v4 = self._create_subnet(network_id, cidr='192.168.10.1/24')
        self._create_subnet(network_id, cidr='fc00::/7')

        self._create_mac_address_range()
        device_id = 'onetwothree'
        port_id = self._create_port(network_id, device_id)['id']

        ip_address = {'ip_address': {'network_id': network_id,
                                     'device_id': device_id,
                                     'version': 4}}
        response = self.plugin.create_ip_address(self.context,
                                                 ip_address)

        self.assertIsNotNone(response['id'])
        self.assertEqual(response['network_id'], network_id)
        self.assertIn(netaddr.IPAddress(response['address']),
                      netaddr.IPNetwork(subnet_v4['cidr']))
        self.assertEqual(response['port_ids'], [port_id])
        self.assertEqual(response['subnet_id'], subnet_v4['id'])

    def test_create_ip_address_ipv6(self):
        network_id = self._create_network()['id']
        subnet_v6 = self._create_subnet(network_id, cidr='fc00::/7')
        self._create_subnet(network_id, cidr='192.168.10.1/24')

        self._create_mac_address_range()
        device_id = 'onetwothree'
        port_id = self._create_port(network_id, device_id)['id']

        ip_address = {'ip_address': {'network_id': network_id,
                                     'device_id': device_id,
                                     'version': 6}}
        response = self.plugin.create_ip_address(self.context,
                                                 ip_address)

        self.assertIsNotNone(response['id'])
        self.assertEqual(response['network_id'], network_id)
        self.assertIn(netaddr.IPAddress(response['address']),
                      netaddr.IPNetwork(subnet_v6['cidr']))
        self.assertEqual(response['port_ids'], [port_id])
        self.assertEqual(response['subnet_id'], subnet_v6['id'])

    def test_create_ip_address_invalid_version(self):
        network_id = self._create_network()['id']
        self._create_subnet(network_id)
        self._create_mac_address_range()
        device_id = 'onetwothree'
        self._create_port(network_id, device_id)

        with self.assertRaises(exceptions.IpAddressGenerationFailure):
            ip_address = {'ip_address': {'network_id': network_id,
                                         'device_id': device_id,
                                         'version': 10}}
            self.plugin.create_ip_address(self.context, ip_address)

    def test_create_ip_address_new(self):
        network_id = self._create_network()['id']
        subnet = self._create_subnet(network_id)
        self._create_mac_address_range()
        port = self._create_port(network_id)

        magic_ip = '192.168.10.123'
        self.assertNotEqual(magic_ip, port['fixed_ips'][0]['ip_address'])

        ip_address = {'ip_address': {'port_id': port['id'],
                                     'ip_address': magic_ip}}
        response = self.plugin.create_ip_address(self.context,
                                                 ip_address)

        self.assertIsNotNone(response['id'])
        self.assertEqual(response['network_id'], network_id)
        self.assertEqual(response['address'], magic_ip)
        self.assertEqual(response['port_ids'], [port['id']])
        self.assertEqual(response['subnet_id'], subnet['id'])

    def test_create_ip_address_new_with_port(self):
        network_id = self._create_network()['id']
        subnet = self._create_subnet(network_id)
        self._create_mac_address_range()
        port = self._create_port(network_id)

        magic_ip = port['fixed_ips'][0]['ip_address']
        ip_address = {'ip_address': {'port_id': port['id'],
                                     'ip_address': magic_ip}}
        response = self.plugin.create_ip_address(self.context,
                                                 ip_address)

        self.assertIsNotNone(response['id'])
        self.assertEqual(response['network_id'], network_id)
        self.assertEqual(response['address'], magic_ip)
        self.assertEqual(response['port_ids'], [port['id']])
        self.assertEqual(response['subnet_id'], subnet['id'])

    def test_get_ip_address_success(self):
        pass

    def test_get_ip_address_failure(self):
        pass

    def test_get_ip_addresses_success(self):
        pass

    def test_update_ip_address_does_not_exist(self):
        with self.assertRaises(exceptions.NotFound):
            self.plugin.update_ip_address(self.context,
                                          'no_ip_address_id',
                                          {'ip_address': {'port_ids': []}})

    def test_update_ip_address_port_not_found(self):
        network_id = self._create_network()['id']
        self._create_subnet(network_id)
        self._create_mac_address_range()
        device_id = 'onetwothree'
        self._create_port(network_id, device_id)

        ip_address = {'ip_address': {'network_id': network_id,
                                     'device_id': device_id}}
        response = self.plugin.create_ip_address(self.context,
                                                 ip_address)

        with self.assertRaises(exceptions.NotFound):
            ip_address = {'ip_address': {'port_ids': ['fake']}}
            self.plugin.update_ip_address(self.context,
                                          response['id'],
                                          ip_address)

    def test_update_ip_address_specify_ports(self):
        network_id = self._create_network()['id']
        self._create_subnet(network_id)
        self._create_mac_address_range()
        port = self._create_port(network_id, device_id='abc')
        port_2 = self._create_port(network_id, device_id='def')

        ip_address = {'ip_address': {'port_id': port['id']}}
        response = self.plugin.create_ip_address(self.context,
                                                 ip_address)
        ip_address = {'ip_address': {'port_ids': [port_2['id']]}}
        response = self.plugin.update_ip_address(self.context,
                                                 response['id'],
                                                 ip_address)
        self.assertEqual(response['port_ids'], [port_2['id']])

    def test_update_ip_address_no_ports(self):
        network_id = self._create_network()['id']
        self._create_subnet(network_id)
        self._create_mac_address_range()
        port = self._create_port(network_id)

        ip_address = {'ip_address': {'port_id': port['id']}}
        response = self.plugin.create_ip_address(self.context,
                                                 ip_address)
        ip_address = {'ip_address': {}}
        response = self.plugin.update_ip_address(self.context,
                                                 response['id'],
                                                 ip_address)
        self.assertEqual(response['port_ids'], [port['id']])

    def test_update_ip_address_empty_ports_delete(self):
        network_id = self._create_network()['id']
        self._create_subnet(network_id)
        self._create_mac_address_range()
        port = self._create_port(network_id)

        ip_address = {'ip_address': {'port_id': port['id']}}
        response = self.plugin.create_ip_address(self.context,
                                                 ip_address)
        ip_address = {'ip_address': {'port_ids': []}}
        response = self.plugin.update_ip_address(self.context,
                                                 response['id'],
                                                 ip_address)
        self.assertEqual(response['port_ids'], [])


class TestQuarkGetPorts(TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, ports=None):
        port_models = []
        if isinstance(ports, list):
            for port in ports:
                port_model = models.Port()
                port_model.update(port)
                port_models.append(port_model)
        elif ports is None:
            port_models = None
        else:
            port_model = models.Port()
            port_model.update(ports)
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

    def test_port_list_with_ports(self):
        port = dict(mac_address="AA:BB:CC:DD:EE:FF", network_id=1,
                    tenant_id=self.context.tenant_id, device_id=2)
        expected = {'status': None,
                    'device_owner': None,
                    'mac_address': 'AA:BB:CC:DD:EE:FF',
                    'network_id': 1,
                    'tenant_id': self.context.tenant_id,
                    'admin_state_up': None,
                    'fixed_ips': [],
                    'device_id': 2}
        with self._stubs(ports=[port]):
            ports = self.plugin.get_ports(self.context, filters=None,
                                          fields=None)
            self.assertEqual(len(ports), 1)
            for key in expected.keys():
                self.assertEqual(ports[0][key], expected[key])

    def test_port_show(self):
        port = dict(mac_address="AA:BB:CC:DD:EE:FF", network_id=1,
                    tenant_id=self.context.tenant_id, device_id=2)
        expected = {'status': None,
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


class TestQuarkCreatePort(TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, port=None, network=None, addr=None, mac=None):
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
            alloc_ip.return_value = addr
            alloc_mac.return_value = mac
            yield port_create

    def test_create_port(self):
        network = dict(id=1)
        mac = dict(address="AA:BB:CC:DD:EE:FF")
        ip = dict()
        port = dict(port=dict(mac_address=mac["address"], network_id=1,
                              tenant_id=self.context.tenant_id, device_id=2))
        expected = {'status': None,
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

    def test_create_port_no_network_found(self):
        port = dict(port=dict(network_id=1, tenant_id=self.context.tenant_id,
                              device_id=2))
        with self._stubs(network=None, port=port["port"]):
            with self.assertRaises(exceptions.NetworkNotFound):
                self.plugin.create_port(self.context, port)


class TestQuarkUpdatePort(TestQuarkPlugin):
    def test_update_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            self.plugin.update_port(self.context, 1, {})


class TestQuarkDeletePort(TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, port=None, addr=None, mac=None):
        port_models = None
        if port:
            port_model = models.Port()
            port_model.update(port)
            port_models = port_model

        db_mod = "quark.db.api"
        ipam = "quark.ipam.QuarkIpam"
        with contextlib.nested(
            mock.patch("%s.port_find" % db_mod),
            mock.patch("%s.deallocate_ip_address" % ipam),
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
