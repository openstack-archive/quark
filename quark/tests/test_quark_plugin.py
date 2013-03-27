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

from quark.db import api as quark_db_api
from quark.db import models
from quark import exceptions as quark_exceptions
import quark.plugin

from quark.tests import test_base


class TestQuarkPlugin(test_base.TestBase):
    def setUp(self):
        cfg.CONF.set_override('sql_connection', 'sqlite://', 'DATABASE')
        db_api.configure_db()
        self.context = context.get_admin_context()
        self.plugin = quark.plugin.Plugin()

    def tearDown(self):
        db_api.clear_db()


class TestQuarkGetSubnetCount(TestQuarkPlugin):
    def test_get_subnet_count(self):
        """This isn't really testable."""
        with mock.patch("quark.db.api.subnet_count_all"):
            self.plugin.get_subnets_count(self.context, {})


class TestQuarkAPIExtensions(TestQuarkPlugin):
    """Adds coverage for appending the API extension path."""
    def test_append_quark_extensions(self):
        quark.plugin.append_quark_extensions({})

    def test_append_no_extension_path(self):
        opts = [cfg.StrOpt("api_extensions_path")]
        quark.plugin.CONF.register_opts(opts)
        quark.plugin.append_quark_extensions(quark.plugin.CONF)


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
                self.assertEqual(res[key], subnet["subnet"][key])

    def test_create_subnet_no_network_fails(self):
        subnet = dict(subnet=dict(network_id=1))
        with self._stubs(subnet=dict(), network=None):
            with self.assertRaises(exceptions.NetworkNotFound):
                self.plugin.create_subnet(self.context, subnet)


class TestQuarkUpdateSubnet(TestQuarkPlugin):
    def test_update_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            self.plugin.update_subnet(self.context, 1, {})


class TestQuarkDeleteSubnet(TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, subnet, ips):
        ip_mods = []
        subnet_mod = None
        if subnet:
            subnet_mod = models.Subnet()
            subnet_mod.update(subnet)
        for ip in ips:
            ip_mod = models.IPAddress()
            ip_mod.update(ip)
            ip_mods.append(ip_mod)

        db_mod = "quark.db.api"
        with contextlib.nested(
            mock.patch("%s.subnet_find" % db_mod),
            mock.patch("%s.subnet_delete" % db_mod)
        ) as (sub_find, sub_delete):
            if subnet_mod:
                subnet_mod.allocated_ips = ip_mods
            sub_find.return_value = subnet_mod
            yield sub_delete

    def test_delete_subnet(self):
        subnet = dict(id=1)
        with self._stubs(subnet=subnet, ips=[]) as sub_delete:
            self.plugin.delete_subnet(self.context, 1)
            self.assertTrue(sub_delete.called)

    def test_delete_subnet_no_subnet_fails(self):
        with self._stubs(subnet=None, ips=[]):
            with self.assertRaises(exceptions.SubnetNotFound):
                self.plugin.delete_subnet(self.context, 1)

    def test_delete_subnet_has_allocated_ips_fails(self):
        subnet = dict(id=1)
        with self._stubs(subnet=subnet, ips=[{}]):
            with self.assertRaises(exceptions.SubnetInUse):
                self.plugin.delete_subnet(self.context, 1)


class TestQuarkGetNetworks(TestQuarkPlugin):
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
                   status="active")
        with self._stubs(nets=[net], subnets=[subnet]):
            nets = self.plugin.get_networks(self.context, {})
            for key in net.keys():
                self.assertEqual(nets[0][key], net[key])
            self.assertEqual(nets[0]["subnets"][0], 1)

    def test_get_network(self):
        subnet = dict(id=1)
        net = dict(id=1, tenant_id=self.context.tenant_id, name="public",
                   status="active")
        expected = net.copy()
        expected["admin_state_up"] = None
        expected["shared"] = None
        expected["status"] = "active"
        with self._stubs(nets=net, subnets=[subnet]):
            res = self.plugin.get_network(self.context, 1)
            for key in expected.keys():
                self.assertEqual(res[key], expected[key])
            self.assertEqual(res["subnets"][0], 1)

    def test_get_network_no_network_fails(self):
        with self._stubs(nets=None, subnets=[]):
            with self.assertRaises(exceptions.NetworkNotFound):
                self.plugin.get_network(self.context, 1)


class TestQuarkGetNetworkCount(TestQuarkPlugin):
    def test_get_port_count(self):
        """This isn't really testable."""
        with mock.patch("quark.db.api.network_count_all"):
            self.plugin.get_networks_count(self.context, {})


class TestQuarkUpdateNetwork(TestQuarkPlugin):
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
        with self._stubs(net=net) as net_update:
            self.plugin.update_network(self.context, 1, dict(network=net))
            self.assertTrue(net_update.called)

    def test_update_network_not_found_fails(self):
        with self._stubs(net=None):
            with self.assertRaises(exceptions.NetworkNotFound):
                self.plugin.update_network(self.context, 1, None)


class TestQuarkDeleteNetwork(TestQuarkPlugin):
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


class TestQuarkCreateNetwork(TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, net=None, subnet=None, ports=None):
        net_mod = net
        subnet_mod = None
        if net:
            net_mod = models.Network()
            net_mod.update(net)

        if subnet:
            subnet_mod = models.Subnet()
            subnet_mod.update(subnet)

        db_mod = "quark.db.api"
        with contextlib.nested(
            mock.patch("%s.network_create" % db_mod),
            mock.patch("%s.subnet_create" % db_mod),
            mock.patch("quark.drivers.base.BaseDriver.create_network"),
        ) as (net_create, sub_create, driver_net_create):
            net_create.return_value = net_mod
            sub_create.return_value = subnet_mod
            yield net_create

    def test_create_network(self):
        net = dict(id=1, name="public")
        with self._stubs(net=net) as net_create:
            net = self.plugin.create_network(self.context, dict(network=net))
            self.assertTrue(net_create.called)

    def test_create_network_with_subnets(self):
        net = dict(id=1, name="public")
        subnet = dict(subnet=dict(id=1, network_id=net["id"],
                      tenant_id=self.context.tenant_id))
        with self._stubs(net=net, subnet=subnet["subnet"]) as net_create:
            net_dict = dict(network=net.copy())
            net_dict["network"]["subnets"] = [subnet]
            res = self.plugin.create_network(self.context, net_dict)
            self.assertTrue(net_create.called)
            self.assertEqual(res["id"], net["id"])
            self.assertEqual(res["name"], net["name"])
            self.assertEqual(res["subnets"][0], net["id"])


class TestIpAddresses(TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, port, addr):
        port_model = None
        addr_model = None
        if port:
            port_model = models.Port()
            port_model.update(port)
        if addr:
            addr_model = models.IPAddress()
            addr_model.update(addr)
        with contextlib.nested(
            mock.patch("quark.db.api.port_find"),
            mock.patch("quark.ipam.QuarkIpam.allocate_ip_address")
        ) as (port_find, alloc_ip):
            port_find.return_value = port_model
            alloc_ip.return_value = addr_model
            yield

    def test_create_ip_address_by_network_and_device(self):
        port = dict(id=1, network_id=2, ip_addresses=[])
        ip = dict(id=1, address=3232235876, address_readable="192.168.1.100",
                  subnet_id=1, network_id=2, version=4)
        with self._stubs(port=port, addr=ip):
            ip_address = dict(network_id=ip["network_id"],
                              device_id=4)
            response = self.plugin.create_ip_address(
                self.context, dict(ip_address=ip_address))

            self.assertIsNotNone(response['id'])
            self.assertEqual(response['network_id'], ip_address["network_id"])
            self.assertEqual(response['port_ids'], [port["id"]])
            self.assertEqual(response['subnet_id'], ip['subnet_id'])

    def test_create_ip_address_with_port(self):
        port = dict(id=1, network_id=2, ip_addresses=[])
        ip = dict(id=1, address=3232235876, address_readable="192.168.1.100",
                  subnet_id=1, network_id=2, version=4)
        with self._stubs(port=port, addr=ip):
            ip_address = dict(port_id=port["id"])
            response = self.plugin.create_ip_address(
                self.context, dict(ip_address=ip_address))

            self.assertIsNotNone(response['id'])
            self.assertEqual(response['network_id'], ip["network_id"])
            self.assertEqual(response['port_ids'], [port["id"]])
            self.assertEqual(response['subnet_id'], ip['id'])

    def test_create_ip_address_invalid_network_and_device(self):
        with self._stubs(port=None, addr=None):
            with self.assertRaises(exceptions.PortNotFound):
                ip_address = {'ip_address': {'network_id': 'fake',
                                             'device_id': 'fake'}}
                self.plugin.create_ip_address(self.context, ip_address)

    def test_create_ip_address_invalid_port(self):
        with self._stubs(port=None, addr=None):
            with self.assertRaises(exceptions.PortNotFound):
                ip_address = {'ip_address': {'port_id': 'fake'}}
                self.plugin.create_ip_address(self.context, ip_address)


class TestQuarkUpdateIPAddress(TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, ports, addr, addr_ports=False):
        port_models = []
        addr_model = None
        for port in ports:
            port_model = models.Port()
            port_model.update(port)
            port_models.append(port_model)
        if addr:
            addr_model = models.IPAddress()
            addr_model.update(addr)
            if addr_ports:
                addr_model.ports = port_models

        db_mod = "quark.db.api"
        with contextlib.nested(
            mock.patch("%s.port_find" % db_mod),
            mock.patch("%s.ip_address_find" % db_mod),
        ) as (port_find, ip_find):
            port_find.return_value = port_models
            ip_find.return_value = addr_model
            yield

    def test_update_ip_address_does_not_exist(self):
        with self._stubs(ports=[], addr=None):
            with self.assertRaises(exceptions.NotFound):
                self.plugin.update_ip_address(self.context,
                                              'no_ip_address_id',
                                              {'ip_address': {'port_ids': []}})

    def test_update_ip_address_port_not_found(self):
        ip = dict(id=1, address=3232235876, address_readable="192.168.1.100",
                  subnet_id=1, network_id=2, version=4)
        with self._stubs(ports=[], addr=ip):
            with self.assertRaises(exceptions.NotFound):
                ip_address = {'ip_address': {'port_ids': ['fake']}}
                self.plugin.update_ip_address(self.context,
                                              ip["id"],
                                              ip_address)

    def test_update_ip_address_specify_ports(self):
        port = dict(id=1, network_id=2, ip_addresses=[])
        ip = dict(id=1, address=3232235876, address_readable="192.168.1.100",
                  subnet_id=1, network_id=2, version=4)
        with self._stubs(ports=[port], addr=ip):
            ip_address = {'ip_address': {'port_ids': [port['id']]}}
            response = self.plugin.update_ip_address(self.context,
                                                     ip['id'],
                                                     ip_address)
            self.assertEqual(response['port_ids'], [port['id']])

    def test_update_ip_address_no_ports(self):
        port = dict(id=1, network_id=2, ip_addresses=[])
        ip = dict(id=1, address=3232235876, address_readable="192.168.1.100",
                  subnet_id=1, network_id=2, version=4)
        with self._stubs(ports=[port], addr=ip):
            ip_address = {'ip_address': {}}
            response = self.plugin.update_ip_address(self.context,
                                                     ip['id'],
                                                     ip_address)
            self.assertEqual(response['port_ids'], [])

    def test_update_ip_address_empty_ports_delete(self):
        port = dict(id=1, network_id=2, ip_addresses=[])
        ip = dict(id=1, address=3232235876, address_readable="192.168.1.100",
                  subnet_id=1, network_id=2, version=4)
        with self._stubs(ports=[port], addr=ip, addr_ports=True):
            ip_address = {'ip_address': {'port_ids': []}}
            response = self.plugin.update_ip_address(self.context,
                                                     ip['id'],
                                                     ip_address)
            self.assertEqual(response['port_ids'], [])


class TestQuarkGetPorts(TestQuarkPlugin):
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

    def test_port_list_with_ports(self):
        ip = dict(id=1, address=3232235876, address_readable="192.168.1.100",
                  subnet_id=1, network_id=2, version=4)
        port = dict(mac_address="aa:bb:cc:dd:ee:ff", network_id=1,
                    tenant_id=self.context.tenant_id, device_id=2)
        expected = {'status': None,
                    'device_owner': None,
                    'mac_address': 'aa:bb:cc:dd:ee:ff',
                    'network_id': 1,
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
        expected = {'status': None,
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
        expected = {'status': None,
                    'device_owner': None,
                    'mac_address': 'aa:bb:cc:dd:ee:ff',
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
        mac = dict(address="aa:bb:cc:dd:ee:ff")
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


class TestQuarkGetPortCount(TestQuarkPlugin):
    def test_get_port_count(self):
        """This isn't really testable."""
        with mock.patch("quark.db.api.port_count_all"):
            self.plugin.get_ports_count(self.context, {})


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


class TestQuarkDisassociatePort(TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, port=None):
        port_models = None
        if port:
            port_model = models.Port()
            port_model.update(port)
            port_models = port_model

        db_mod = "quark.db.api"
        with mock.patch("%s.port_find" % db_mod) as port_find:
            port_find.return_value = port_models
            yield port_find

    def test_port_disassociate_port(self):
        ip = dict(id=1, address=3232235876, address_readable="192.168.1.100",
                  subnet_id=1, network_id=2, version=4)
        fixed_ips = [{"subnet_id": ip["subnet_id"],
                      "ip_address": ip["address_readable"]}]
        port = dict(port=dict(network_id=1, tenant_id=self.context.tenant_id,
                              device_id=2, mac_address="AA:BB:CC:DD:EE:FF",
                              backend_key="foo", fixed_ips=fixed_ips))
        with self._stubs(port=port["port"]) as (port_find):
            new_port = self.plugin.disassociate_port(self.context, 1, 1)
            port_find.assert_called_with(self.context,
                                         id=1,
                                         ip_address_id=[1],
                                         scope=quark_db_api.ONE)
            self.assertEqual(new_port["fixed_ips"], [])

    def test_port_disassociate_port_not_found_fails(self):
        with self._stubs(port=None):
            with self.assertRaises(exceptions.PortNotFound):
                self.plugin.disassociate_port(self.context, 1, 1)


class TestQuarkGetMacAddressRanges(TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, mac_range):
        db_mod = "quark.db.api"
        with mock.patch("%s.mac_address_range_find" % db_mod) as mar_find:
            mar_find.return_value = [mac_range]
            yield

    def test_find_mac_ranges(self):
        mar = dict(id=1, cidr="AA:BB:CC/24")
        with self._stubs(mar):
            res = self.plugin.get_mac_address_ranges(self.context)
            self.assertEqual(res[0]["id"], mar["id"])
            self.assertEqual(res[0]["cidr"], mar["cidr"])


class TestQuarkCreateMacAddressRanges(TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, mac_range):
        db_mod = "quark.db.api"
        with mock.patch("%s.mac_address_range_create" % db_mod) as mar_create:
            mar_create.return_value = mac_range
            yield

    def test_create_range(self):
        mar = dict(mac_address_range=dict(id=1, cidr="AA:BB:CC/24"))
        with self._stubs(mar["mac_address_range"]):
            res = self.plugin.create_mac_address_range(self.context, mar)
            self.assertEqual(res["id"], mar["mac_address_range"]["id"])
            self.assertEqual(res["cidr"], mar["mac_address_range"]["cidr"])

    def test_to_mac_range_cidr_format(self):
        cidr, first, last = self.plugin._to_mac_range("AA:BB:CC/24")
        first_mac = str(netaddr.EUI(first, dialect=netaddr.mac_unix))
        last_mac = str(netaddr.EUI(last, dialect=netaddr.mac_unix))
        self.assertEqual(cidr, "AA:BB:CC:00:00:00/24")
        self.assertEqual(first_mac, "aa:bb:cc:0:0:0")
        self.assertEqual(last_mac, "aa:bb:cd:0:0:0")

    def test_to_mac_range_just_prefix(self):
        cidr, first, last = self.plugin._to_mac_range("AA:BB:CC")
        first_mac = str(netaddr.EUI(first, dialect=netaddr.mac_unix))
        last_mac = str(netaddr.EUI(last, dialect=netaddr.mac_unix))
        self.assertEqual(cidr, "AA:BB:CC:00:00:00/24")
        self.assertEqual(first_mac, "aa:bb:cc:0:0:0")
        self.assertEqual(last_mac, "aa:bb:cd:0:0:0")

    def test_to_mac_range_unix_format(self):
        cidr, first, last = self.plugin._to_mac_range("AA-BB-CC")
        first_mac = str(netaddr.EUI(first, dialect=netaddr.mac_unix))
        last_mac = str(netaddr.EUI(last, dialect=netaddr.mac_unix))
        self.assertEqual(cidr, "AA:BB:CC:00:00:00/24")
        self.assertEqual(first_mac, "aa:bb:cc:0:0:0")
        self.assertEqual(last_mac, "aa:bb:cd:0:0:0")

    def test_to_mac_range_unix_cidr_format(self):
        cidr, first, last = self.plugin._to_mac_range("AA-BB-CC/24")
        first_mac = str(netaddr.EUI(first, dialect=netaddr.mac_unix))
        last_mac = str(netaddr.EUI(last, dialect=netaddr.mac_unix))
        self.assertEqual(cidr, "AA:BB:CC:00:00:00/24")
        self.assertEqual(first_mac, "aa:bb:cc:0:0:0")
        self.assertEqual(last_mac, "aa:bb:cd:0:0:0")

    def test_to_mac_prefix_too_short_fails(self):
        with self.assertRaises(quark_exceptions.InvalidMacAddressRange):
            cidr, first, last = self.plugin._to_mac_range("AA-BB")

    def test_to_mac_prefix_too_long_fails(self):
        with self.assertRaises(quark_exceptions.InvalidMacAddressRange):
            cidr, first, last = self.plugin._to_mac_range("AA-BB-CC-DD-EE-F0")

    def test_to_mac_prefix_is_garbage_fails(self):
        with self.assertRaises(quark_exceptions.InvalidMacAddressRange):
            cidr, first, last = self.plugin._to_mac_range("F0-0-BAR")


class TestQuarkGetRoutes(TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, routes):
        with mock.patch("quark.db.api.route_find") as route_find:
            route_find.return_value = routes
            yield

    def test_get_routes(self):
        route = dict(id=1, cidr="192.168.0.0/24", gateway="192.168.0.1",
                     subnet_id=2)
        with self._stubs(routes=[route]):
            res = self.plugin.get_routes(self.context)
            for key in route.keys():
                self.assertEqual(res[0][key], route[key])

    def test_get_route(self):
        route = dict(id=1, cidr="192.168.0.0/24", gateway="192.168.0.1",
                     subnet_id=2)
        with self._stubs(routes=route):
            res = self.plugin.get_route(self.context, 1)
            for key in route.keys():
                self.assertEqual(res[key], route[key])

    def test_get_route_not_found_fails(self):
        with self._stubs(routes=None):
            with self.assertRaises(quark_exceptions.RouteNotFound):
                self.plugin.get_route(self.context, 1)


class TestQuarkCreateRoutes(TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, create_route, find_routes, subnet):
        db_mod = "quark.db.api"
        with contextlib.nested(
            mock.patch("%s.route_create" % db_mod),
            mock.patch("%s.route_find" % db_mod),
            mock.patch("%s.subnet_find" % db_mod)
        ) as (route_create, route_find, subnet_find):
            route_create.return_value = create_route
            route_find.return_value = find_routes
            subnet_find.return_value = subnet
            yield

    def test_create_route(self):
        subnet = dict(id=2)
        create_route = dict(id=1, cidr="172.16.0.0/24", gateway="172.16.0.1",
                            subnet_id=subnet["id"])
        route = dict(id=1, cidr="192.168.0.0/24", gateway="192.168.0.1",
                     subnet_id=subnet["id"])
        with self._stubs(create_route=create_route, find_routes=[route],
                         subnet=subnet):
            res = self.plugin.create_route(self.context,
                                           dict(route=create_route))
            for key in create_route.keys():
                self.assertEqual(res[key], create_route[key])

    def test_create_route_no_subnet_fails(self):
        subnet = dict(id=2)
        route = dict(id=1, cidr="192.168.0.0/24", gateway="192.168.0.1",
                     subnet_id=subnet["id"])
        with self._stubs(create_route=route, find_routes=[], subnet=None):
            with self.assertRaises(exceptions.SubnetNotFound):
                self.plugin.create_route(self.context, dict(route=route))

    def test_create_no_other_routes(self):
        subnet = dict(id=2)
        create_route = dict(id=1, cidr="192.168.0.0/24", gateway="192.168.0.1",
                            subnet_id=subnet["id"])
        with self._stubs(create_route=create_route, find_routes=[],
                         subnet=subnet):
            res = self.plugin.create_route(self.context,
                                           dict(route=create_route))
            self.assertEqual(res["cidr"], create_route["cidr"])

    def test_create_conflicting_route_raises(self):
        subnet = dict(id=2)
        create_route = dict(id=1, cidr="192.168.0.0/24", gateway="192.168.0.1",
                            subnet_id=subnet["id"])
        route = dict(id=1, cidr="192.168.0.0/24", gateway="192.168.0.1",
                     subnet_id=subnet["id"])
        with self._stubs(create_route=create_route, find_routes=[route],
                         subnet=subnet):
            with self.assertRaises(quark_exceptions.RouteConflict):
                self.plugin.create_route(self.context,
                                         dict(route=create_route))


class TestQuarkDeleteRoutes(TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, route):
        db_mod = "quark.db.api"
        with contextlib.nested(
            mock.patch("%s.route_delete" % db_mod),
            mock.patch("%s.route_find" % db_mod),
        ) as (route_delete, route_find):
            route_find.return_value = route
            yield route_delete

    def test_delete_route(self):
        route = dict(id=1, cidr="192.168.0.0/24", gateway="192.168.0.1",
                     subnet_id=2)
        with self._stubs(route=route) as route_delete:
            self.plugin.delete_route(self.context, 1)
            self.assertTrue(route_delete.called)

    def test_delete_route_not_found_fails(self):
        with self._stubs(route=None):
            with self.assertRaises(quark_exceptions.RouteNotFound):
                self.plugin.delete_route(self.context, 1)


class TestQuarkGetIpAddresses(TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, ips, ports):
        with mock.patch("quark.db.api.ip_address_find") as ip_find:
            ip_models = []
            port_models = []
            for port in ports:
                p = models.Port()
                p.update(port)
                port_models.append(p)
            if isinstance(ips, list):
                for ip in ips:
                    version = ip.pop("version")
                    ip_mod = models.IPAddress()
                    ip_mod.update(ip)
                    ip_mod.version = version
                    ip_mod.ports = port_models
                    ip_models.append(ip_mod)
                ip_find.return_value = ip_models
            else:
                if ips:
                    version = ips.pop("version")
                    ip_mod = models.IPAddress()
                    ip_mod.update(ips)
                    ip_mod.version = version
                    ip_mod.ports = port_models
                    ip_find.return_value = ip_mod
                else:
                    ip_find.return_value = ips
            yield

    def test_get_ip_addresses(self):
        port = dict(id=100)
        ip = dict(id=1, address=3232235876, address_readable="192.168.1.100",
                  subnet_id=1, network_id=2, version=4)
        with self._stubs(ips=[ip], ports=[port]):
            res = self.plugin.get_ip_addresses(self.context)
            addr_res = res[0]
            self.assertEqual(ip["id"], addr_res["id"])
            self.assertEqual(ip["subnet_id"], addr_res["subnet_id"])
            self.assertEqual(ip["address_readable"], addr_res["address"])
            self.assertEqual(addr_res["port_ids"][0], port["id"])

    def test_get_ip_address(self):
        port = dict(id=100)
        ip = dict(id=1, address=3232235876, address_readable="192.168.1.100",
                  subnet_id=1, network_id=2, version=4)
        with self._stubs(ips=ip, ports=[port]):
            res = self.plugin.get_ip_address(self.context, 1)
            self.assertEqual(ip["id"], res["id"])
            self.assertEqual(ip["subnet_id"], res["subnet_id"])
            self.assertEqual(ip["address_readable"], res["address"])
            self.assertEqual(res["port_ids"][0], port["id"])

    def test_get_ip_address_no_ip_fails(self):
        port = dict(id=100)
        with self._stubs(ips=None, ports=[port]):
            with self.assertRaises(quark_exceptions.IpAddressNotFound):
                self.plugin.get_ip_address(self.context, 1)
