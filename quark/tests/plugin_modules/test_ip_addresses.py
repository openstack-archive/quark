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

import mock
import webob
from mock import patch
from neutron.common import exceptions

from quark import exceptions as quark_exceptions
from quark.db import models
from quark.tests import test_quark_plugin


class TestIpAddresses(test_quark_plugin.TestQuarkPlugin):
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
                  subnet_id=1, network_id=2, version=4, used_by_tenant_id=1)
        with self._stubs(port=port, addr=ip):
            ip_address = dict(network_id=ip["network_id"],
                              device_ids=[4])
            response = self.plugin.create_ip_address(
                self.context, dict(ip_address=ip_address))

            self.assertIsNotNone(response["id"])
            self.assertEqual(response["network_id"], ip_address["network_id"])
            self.assertEqual(response["device_ids"], [""])
            self.assertEqual(response["port_ids"], [port["id"]])
            self.assertEqual(response["subnet_id"], ip["subnet_id"])
            self.assertFalse(response["shared"])
            self.assertEqual(response["version"], 4)
            self.assertEqual(response["address"], "192.168.1.100")
            self.assertEqual(response["used_by_tenant_id"], 1)

    def test_create_ip_address_with_port(self):
        port = dict(id=1, network_id=2, ip_addresses=[])
        ip = dict(id=1, address=3232235876, address_readable="192.168.1.100",
                  subnet_id=1, network_id=2, version=4)
        with self._stubs(port=port, addr=ip):
            ip_address = dict(port_ids=[port["id"]])
            response = self.plugin.create_ip_address(
                self.context, dict(ip_address=ip_address))

            self.assertIsNotNone(response['id'])
            self.assertEqual(response['network_id'], ip["network_id"])
            self.assertEqual(response['port_ids'], [port["id"]])
            self.assertEqual(response['subnet_id'], ip['id'])

    def test_create_ip_address_by_device_no_network_fails(self):
        with self._stubs(port={}, addr=None):
            ip_address = dict(device_ids=[4])
            with self.assertRaises(exceptions.BadRequest):
                self.plugin.create_ip_address(self.context,
                                              dict(ip_address=ip_address))

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


class TestQuarkUpdateIPAddress(test_quark_plugin.TestQuarkPlugin):
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

    def _create_patch(self, path):
        patcher = patch(path)
        mocked = patcher.start()
        self.addCleanup(patcher.stop)
        return mocked

    def test_update_ip_address_update_deallocated_at(self):
        port = dict(id=1, network_id=2, ip_addresses=[])
        ip = dict(id=1, address=3232235876, address_readable="192.168.1.100",
                  subnet_id=1, network_id=2, version=4, deallocated=1,
                  deallocated_at='2020-01-01 00:00:00')

        path = 'quark.plugin_modules.ip_addresses'
        lookup = self._create_patch('%s._get_deallocated_override' % path)

        with self._stubs(ports=[port], addr=ip):
            ip_address = {'ip_address': {'reset_allocation_time': True}}
            self.plugin.update_ip_address(self.admin_context, ip['id'],
                                          ip_address)
            self.assertTrue(lookup.called)

    def test_update_ip_address_update_deallocated_at_not_deallocated(self):
        port = dict(id=1, network_id=2, ip_addresses=[])
        ip = dict(id=1, address=3232235876, address_readable="192.168.1.100",
                  subnet_id=1, network_id=2, version=4, deallocated=0,
                  deallocated_at='2020-01-01 00:00:00')

        path = 'quark.plugin_modules.ip_addresses'
        lookup = self._create_patch('%s._get_deallocated_override' % path)

        with self._stubs(ports=[port], addr=ip):
            ip_address = {'ip_address': {'reset_allocation_time': True}}
            self.plugin.update_ip_address(self.admin_context, ip['id'],
                                          ip_address)
            self.assertFalse(lookup.called)

    def test_update_ip_address_update_deallocated_at_not_admin(self):
        port = dict(id=1, network_id=2, ip_addresses=[])
        ip = dict(id=1, address=3232235876, address_readable="192.168.1.100",
                  subnet_id=1, network_id=2, version=4, deallocated=1,
                  deallocated_at='2020-01-01 00:00:00')

        with self._stubs(ports=[port], addr=ip):
            ip_address = {'ip_address': {'reset_allocation_time': True}}
            with self.assertRaises(webob.exc.HTTPForbidden):
                self.plugin.update_ip_address(self.context, ip['id'],
                                              ip_address)

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


class TestQuarkGetIpAddresses(test_quark_plugin.TestQuarkPlugin):
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
        port = dict(id=100, device_id="foobar")
        ip = dict(id=1, address=3232235876, address_readable="192.168.1.100",
                  subnet_id=1, network_id=2, version=4)
        with self._stubs(ips=[ip], ports=[port]):
            res = self.plugin.get_ip_addresses(self.context)
            addr_res = res[0]
            self.assertEqual(ip["id"], addr_res["id"])
            self.assertEqual(ip["subnet_id"], addr_res["subnet_id"])
            self.assertEqual(ip["address_readable"], addr_res["address"])
            self.assertEqual(addr_res["port_ids"][0], port["id"])
            self.assertEqual(addr_res["device_ids"][0], port["device_id"])

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
