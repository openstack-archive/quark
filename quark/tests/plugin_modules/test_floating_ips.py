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

import datetime
import mock
import netaddr
from neutron.common import exceptions

from quark.db import models
from quark import exceptions as quark_exceptions
from quark.plugin_modules import floating_ips
from quark.tests import test_quark_plugin


class TestRemoveFloatingIPs(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, flip=None):
        flip_model = None
        if flip:
            flip_model = models.IPAddress()
            flip_model.update(flip)

        with contextlib.nested(
            mock.patch("quark.db.api.floating_ip_find"),
            mock.patch("quark.ipam.QuarkIpam.deallocate_ip_address"),
            mock.patch("quark.drivers.unicorn_driver.UnicornDriver"
                       ".remove_floating_ip")
        ) as (flip_find, mock_dealloc, mock_remove_flip):
            flip_find.return_value = flip_model
            yield

    def test_delete_floating_by_ip_address_id(self):
        flip = dict(id=1, address=3232235876, address_readable="192.168.1.100",
                    subnet_id=1, network_id=2, version=4, used_by_tenant_id=1,
                    network=dict(ipam_strategy="ANY"))
        with self._stubs(flip=flip):
            self.plugin.delete_floatingip(self.context, 1)

    def test_delete_floating_by_when_ip_address_does_not_exists_fails(self):
        with self._stubs():
            with self.assertRaises(quark_exceptions.FloatingIpNotFound):
                self.plugin.delete_floatingip(self.context, 1)


class TestFloatingIPUtilityMethods(test_quark_plugin.TestQuarkPlugin):
    def test_get_next_available_fixed_ip_with_single_fixed_ip(self):
        port = models.Port()
        port.update(dict(id=1))

        fixed_ip_addr = netaddr.IPAddress('192.168.0.1')
        fixed_ip = models.IPAddress()
        fixed_ip.update(dict(address_type="fixed", address=int(fixed_ip_addr),
                             version=4, address_readable=str(fixed_ip_addr),
                             allocated_at=datetime.datetime.now()))

        port.ip_addresses.append(fixed_ip)

        next_fixed_ip = floating_ips._get_next_available_fixed_ip(port)

        self.assertEqual(next_fixed_ip["address_readable"], '192.168.0.1')

    def test_get_next_available_fixed_ip_with_mult_fixed_ips(self):
        port = models.Port()
        port.update(dict(id=1))

        for ip_addr in ["192.168.0.1", "192.168.0.2", "192.168.0.3"]:
            fixed_ip_addr = netaddr.IPAddress(ip_addr)
            fixed_ip = models.IPAddress()
            fixed_ip.update(dict(address_type="fixed",
                                 address=int(fixed_ip_addr),
                                 version=4,
                                 address_readable=str(fixed_ip_addr),
                                 allocated_at=datetime.datetime.now()))

            port.ip_addresses.append(fixed_ip)

        next_fixed_ip = floating_ips._get_next_available_fixed_ip(port)

        self.assertEqual(next_fixed_ip["address_readable"], '192.168.0.1')

    def test_get_next_available_fixed_ip_with_no_avail_fixed_ips(self):
        port = models.Port()
        port.update(dict(id=1))

        fixed_ip_addr = netaddr.IPAddress("192.168.0.1")
        fixed_ip = models.IPAddress()
        fixed_ip.update(dict(address_type="fixed",
                             address=int(fixed_ip_addr),
                             version=4,
                             address_readable=str(fixed_ip_addr),
                             allocated_at=datetime.datetime.now()))

        flip_addr = netaddr.IPAddress("10.0.0.1")
        flip = models.IPAddress()
        flip.update(dict(address_type="floating",
                         address=int(flip_addr),
                         version=4,
                         address_readable=str(flip_addr),
                         allocated_at=datetime.datetime.now()))
        flip.fixed_ip = fixed_ip

        port.ip_addresses.append(fixed_ip)
        port.ip_addresses.append(flip)

        fixed_ip_addr = netaddr.IPAddress("192.168.0.2")
        fixed_ip = models.IPAddress()
        fixed_ip.update(dict(address_type="fixed",
                             address=int(fixed_ip_addr),
                             version=4,
                             address_readable=str(fixed_ip_addr),
                             allocated_at=datetime.datetime.now()))

        flip_addr = netaddr.IPAddress("10.0.0.2")
        flip = models.IPAddress()
        flip.update(dict(address_type="floating",
                         address=int(flip_addr),
                         version=4,
                         address_readable=str(flip_addr),
                         allocated_at=datetime.datetime.now()))
        flip.fixed_ip = fixed_ip

        port.ip_addresses.append(fixed_ip)
        port.ip_addresses.append(flip)

        next_fixed_ip = floating_ips._get_next_available_fixed_ip(port)

        self.assertEqual(next_fixed_ip, None)

    def test_get_next_available_fixed_ip_with_avail_fixed_ips(self):
        port = models.Port()
        port.update(dict(id=1))

        fixed_ip_addr = netaddr.IPAddress("192.168.0.1")
        fixed_ip = models.IPAddress()
        fixed_ip.update(dict(address_type="fixed",
                             address=int(fixed_ip_addr),
                             version=4,
                             address_readable=str(fixed_ip_addr),
                             allocated_at=datetime.datetime.now()))

        flip_addr = netaddr.IPAddress("10.0.0.1")
        flip = models.IPAddress()
        flip.update(dict(address_type="floating",
                         address=int(flip_addr),
                         version=4,
                         address_readable=str(flip_addr),
                         allocated_at=datetime.datetime.now()))
        flip.fixed_ip = fixed_ip

        port.ip_addresses.append(fixed_ip)
        port.ip_addresses.append(flip)

        fixed_ip_addr = netaddr.IPAddress("192.168.0.2")
        fixed_ip = models.IPAddress()
        fixed_ip.update(dict(address_type="fixed",
                             address=int(fixed_ip_addr),
                             version=4,
                             address_readable=str(fixed_ip_addr),
                             allocated_at=datetime.datetime.now()))

        port.ip_addresses.append(fixed_ip)
        port.ip_addresses.append(flip)

        next_fixed_ip = floating_ips._get_next_available_fixed_ip(port)

        self.assertEqual(next_fixed_ip["address_readable"], "192.168.0.2")


class TestCreateFloatingIPs(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, flip=None, port=None, ips=None, network=None):
        port_model = None
        if port:
            port_model = models.Port()
            port_model.update(dict(port=port))
            if ips:
                for ip in ips:
                    ip_model = models.IPAddress()
                    ip_model.update(ip)
                    if (ip["address_type"] == "floating"
                       and "fixed_ip_addr" in ip):
                        fixed_ip = models.IPAddress()
                        fixed_ip.update(next(ip_addr for ip_addr in ips
                                             if (ip_addr["address_readable"] ==
                                                 ip["fixed_ip_addr"])))
                        ip_model.fixed_ip = fixed_ip
                    port_model.ip_addresses.append(ip_model)

        flip_model = None
        if flip:
            flip_model = models.IPAddress()
            flip_model.update(flip)

        net_model = None
        if network:
            net_model = models.Network()
            net_model.update(network)

        def _alloc_ip(context, new_addr, net_id, port_m, *args, **kwargs):
            new_addr.append(flip_model)

        def _flip_fixed_ip_assoc(context, addr, fixed_ip):
            addr.fixed_ip = fixed_ip
            return addr

        with contextlib.nested(
            mock.patch("quark.db.api.floating_ip_find"),
            mock.patch("quark.db.api.network_find"),
            mock.patch("quark.db.api.port_find"),
            mock.patch("quark.ipam.QuarkIpam.allocate_ip_address"),
            mock.patch("quark.drivers.unicorn_driver.UnicornDriver"
                       ".register_floating_ip"),
            mock.patch("quark.db.api.floating_ip_associate_fixed_ip")
        ) as (flip_find, net_find, port_find, alloc_ip, mock_reg_flip, assoc):
            flip_find.return_value = flip_model
            net_find.return_value = net_model
            port_find.return_value = port_model
            alloc_ip.side_effect = _alloc_ip
            assoc.side_effect = _flip_fixed_ip_assoc
            yield

    def test_create_with_a_port(self):
        floating_ip_addr = netaddr.IPAddress("10.0.0.1")
        floating_ip = dict(id=1, address=int(floating_ip_addr), version=4,
                           address_readable=str(floating_ip_addr), subnet_id=1,
                           network_id=2, used_by_tenant_id=1)
        network = dict(id="00000000-0000-0000-0000-000000000000",
                       ipam_strategy="ANY")

        fixed_ip_addr = netaddr.IPAddress("192.168.0.1")
        fixed_ips = [dict(address_type="fixed", address=int(fixed_ip_addr),
                          version=4, address_readable=str(fixed_ip_addr),
                          allocated_at=datetime.datetime.now())]
        port = dict(id="abcdefgh-1111-2222-3333-1234567890ab")

        with self._stubs(flip=floating_ip, port=port,
                         ips=fixed_ips, network=network):
            request = dict(floating_network_id=network["id"],
                           port_id=port["id"])
            flip = self.plugin.create_floatingip(self.context,
                                                 dict(floatingip=request))
            self.assertEqual(flip["floating_ip_address"], "10.0.0.1")
            self.assertEqual(flip["fixed_ip_address"], "192.168.0.1")

    def test_create_without_a_port(self):
        floating_ip_addr = netaddr.IPAddress("10.0.0.1")
        floating_ip = dict(id=1, address=int(floating_ip_addr), version=4,
                           address_readable=str(floating_ip_addr), subnet_id=1,
                           network_id=2, used_by_tenant_id=1)
        network = dict(id="00000000-0000-0000-0000-000000000000",
                       ipam_strategy="ANY")

        fixed_ip_addr = netaddr.IPAddress("192.168.0.1")
        fixed_ips = [dict(address_type="fixed", address=int(fixed_ip_addr),
                          version=4, address_readable=str(fixed_ip_addr),
                          allocated_at=datetime.datetime.now())]

        with self._stubs(flip=floating_ip, port=None,
                         ips=fixed_ips, network=network):
            request = dict(floating_network_id=network["id"], port_id=None)
            flip = self.plugin.create_floatingip(self.context,
                                                 dict(floatingip=request))
            self.assertEqual(flip["floating_ip_address"], "10.0.0.1")
            self.assertEqual(flip.get("fixed_ip_address"), None)

    def test_create_with_fixed_ip_specified(self):
        floating_ip_addr = netaddr.IPAddress("10.0.0.1")
        floating_ip = dict(id=1, address=int(floating_ip_addr), version=4,
                           address_readable=str(floating_ip_addr), subnet_id=1,
                           network_id=2, used_by_tenant_id=1)
        network = dict(id="00000000-0000-0000-0000-000000000000",
                       ipam_strategy="ANY")

        fixed_ips = []
        for ip_addr in ["192.168.0.1", "192.168.0.2"]:
            fixed_ip_addr = netaddr.IPAddress(ip_addr)
            fixed_ips.append(dict(address_type="fixed", version=4,
                                  address=int(fixed_ip_addr),
                                  address_readable=str(fixed_ip_addr),
                                  allocated_at=datetime.datetime.now()))

        port = dict(id="abcdefgh-1111-2222-3333-1234567890ab")

        with self._stubs(flip=floating_ip, port=port,
                         ips=fixed_ips, network=network):
            request = dict(floating_network_id=network["id"],
                           port_id=port["id"], fixed_ip_address="192.168.0.2")
            flip = self.plugin.create_floatingip(self.context,
                                                 dict(floatingip=request))
            self.assertEqual(flip["floating_ip_address"], "10.0.0.1")
            self.assertEqual(flip["fixed_ip_address"], "192.168.0.2")

    def test_create_with_floating_ip_specified(self):
        floating_ip_addr = netaddr.IPAddress("10.0.0.1")
        floating_ip = dict(id=1, address=int(floating_ip_addr), version=4,
                           address_readable=str(floating_ip_addr), subnet_id=1,
                           network_id=2, used_by_tenant_id=1)
        network = dict(id="00000000-0000-0000-0000-000000000000",
                       ipam_strategy="ANY")

        fixed_ip_addr = netaddr.IPAddress("192.168.0.1")
        fixed_ips = [dict(address_type="fixed", address=int(fixed_ip_addr),
                          version=4, address_readable=str(fixed_ip_addr),
                          allocated_at=datetime.datetime.now())]
        port = dict(id=2)

        with self._stubs(flip=floating_ip, port=port,
                         ips=fixed_ips, network=network):
            request = dict(floating_network_id=network["id"],
                           port_id=port["id"], floating_ip_address="10.0.0.1")
            flip = self.plugin.create_floatingip(self.context,
                                                 dict(floatingip=request))
            self.assertEqual(flip["floating_ip_address"], "10.0.0.1")
            self.assertEqual(flip["fixed_ip_address"], "192.168.0.1")

    def test_create_without_network_id_fails(self):
        with self._stubs():
            with self.assertRaises(exceptions.BadRequest):
                request = dict(port_id=2, floating_ip_address="10.0.0.1")
                self.plugin.create_floatingip(self.context,
                                              dict(floatingip=request))

    def test_create_with_invalid_network_fails(self):
        with self._stubs():
            with self.assertRaises(exceptions.NetworkNotFound):
                request = dict(floating_network_id=123,
                               port_id=2, floating_ip_address="10.0.0.1")
                self.plugin.create_floatingip(self.context,
                                              dict(floatingip=request))

    def test_create_with_invalid_port_fails(self):
        network = dict(id="00000000-0000-0000-0000-000000000000",
                       ipam_strategy="ANY")

        with self._stubs(network=network):
            with self.assertRaises(exceptions.PortNotFound):
                request = dict(floating_network_id=network["id"],
                               port_id=2, floating_ip_address="10.0.0.1")
                self.plugin.create_floatingip(self.context,
                                              dict(floatingip=request))

    def test_create_with_invalid_fixed_ip_for_port_fails(self):
        network = dict(id="00000000-0000-0000-0000-000000000000",
                       ipam_strategy="ANY")

        fixed_ip_addr = netaddr.IPAddress("192.168.0.1")
        fixed_ips = [dict(address_type="fixed", version=4,
                          address=int(fixed_ip_addr),
                          address_readable=str(fixed_ip_addr),
                          allocated_at=datetime.datetime.now())]

        port = dict(id="abcdefgh-1111-2222-3333-1234567890ab")

        with self._stubs(port=port, ips=fixed_ips, network=network):
            with self.assertRaises(
                    quark_exceptions.FixedIpDoesNotExistsForPort):
                request = dict(floating_network_id=network["id"],
                               port_id=port["id"],
                               fixed_ip_address="192.168.0.2")
                flip = self.plugin.create_floatingip(self.context,
                                                     dict(floatingip=request))
                self.assertEqual(flip["address_readable"], "10.0.0.1")
                self.assertEqual(flip.fixed_ip["address_readable"],
                                 "192.168.0.2")

    def test_create_with_port_and_fixed_ip_with_existing_flip_fails(self):
        network = dict(id="00000000-0000-0000-0000-000000000000",
                       ipam_strategy="ANY")

        fixed_ip_addr = netaddr.IPAddress("192.168.0.1")
        fixed_ip = dict(address_type="fixed", version=4,
                        address=int(fixed_ip_addr),
                        address_readable=str(fixed_ip_addr),
                        allocated_at=datetime.datetime.now())

        floating_ip_addr = netaddr.IPAddress("10.0.0.1")
        floating_ip = dict(address_type="floating", version=4,
                           address=int(floating_ip_addr),
                           address_readable=str(floating_ip_addr),
                           allocated_at=datetime.datetime.now(),
                           fixed_ip_addr="192.168.0.1")

        ips = [fixed_ip, floating_ip]

        port = dict(id="abcdefgh-1111-2222-3333-1234567890ab")

        with self._stubs(port=port, ips=ips, network=network):
            with self.assertRaises(
                    quark_exceptions.PortAlreadyContainsFloatingIp):
                request = dict(floating_network_id=network["id"],
                               port_id=port["id"],
                               fixed_ip_address="192.168.0.1")
                self.plugin.create_floatingip(self.context,
                                              dict(floatingip=request))

    def test_create_when_port_has_no_fixed_ips_fails(self):
        network = dict(id="00000000-0000-0000-0000-000000000000",
                       ipam_strategy="ANY")

        port = dict(id="abcdefgh-1111-2222-3333-1234567890ab")

        with self._stubs(port=port, network=network):
            with self.assertRaises(
                    quark_exceptions.NoAvailableFixedIPsForPort):
                request = dict(floating_network_id=network["id"],
                               port_id=port["id"])
                self.plugin.create_floatingip(self.context,
                                              dict(floatingip=request))

    def test_create_when_port_has_no_available_fixed_ips_fails(self):
        network = dict(id="00000000-0000-0000-0000-000000000000",
                       ipam_strategy="ANY")

        fixed_ip_addr = netaddr.IPAddress("192.168.0.1")
        fixed_ip = dict(address_type="fixed", version=4,
                        address=int(fixed_ip_addr),
                        address_readable=str(fixed_ip_addr),
                        allocated_at=datetime.datetime.now())

        floating_ip_addr = netaddr.IPAddress("10.0.0.1")
        floating_ip = dict(address_type="floating", version=4,
                           address=int(floating_ip_addr),
                           address_readable=str(floating_ip_addr),
                           allocated_at=datetime.datetime.now(),
                           fixed_ip_addr="192.168.0.1")

        ips = [fixed_ip, floating_ip]

        port = dict(id="abcdefgh-1111-2222-3333-1234567890ab")

        with self._stubs(port=port, ips=ips, network=network):
            with self.assertRaises(
                    quark_exceptions.NoAvailableFixedIPsForPort):
                request = dict(floating_network_id=network["id"],
                               port_id=port["id"])
                self.plugin.create_floatingip(self.context,
                                              dict(floatingip=request))
