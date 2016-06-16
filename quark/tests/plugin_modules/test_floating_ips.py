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

import datetime
import mock
import netaddr
from neutron.common import exceptions as ex

from quark.db import models
from quark import exceptions as q_ex
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
            mock.patch("quark.db.api.floating_ip_disassociate_fixed_ip"),
            mock.patch("quark.db.api.port_disassociate_ip"),
            mock.patch("quark.db.api.ip_address_deallocate"),
            mock.patch("quark.ipam.QuarkIpam.deallocate_ip_address"),
            mock.patch("quark.drivers.unicorn_driver.UnicornDriver"
                       ".remove_floating_ip"),
            mock.patch("quark.billing.notify"),
            mock.patch("quark.billing.build_payload")
        ) as (flip_find, db_fixed_ip_disassoc, db_port_disassoc, db_dealloc,
              mock_dealloc, mock_remove_flip, notify, build_payload):
            flip_find.return_value = flip_model
            build_payload.return_value = {'respek': '4reelz'}
            yield

    def test_delete_floating_by_ip_address_id(self):
        flip = dict(id=1, address=3232235876, address_readable="192.168.1.100",
                    subnet_id=1, network_id=2, version=4, used_by_tenant_id=1,
                    network=dict(ipam_strategy="ANY"))
        with self._stubs(flip=flip):
            self.plugin.delete_floatingip(self.context, 1)

    def test_delete_floating_by_when_ip_address_does_not_exists_fails(self):
        with self._stubs():
            with self.assertRaises(q_ex.FloatingIpNotFound):
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
                    addr_type = ip.get("address_type")
                    if addr_type == "floating" and "fixed_ip_addr" in ip:
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

        def _port_assoc(context, ports, addr, enable_port=None):
            addr.ports = ports
            return addr

        def _flip_fixed_ip_assoc(context, addr, fixed_ip):
            addr.fixed_ips.append(fixed_ip)
            return addr

        with contextlib.nested(
            mock.patch("quark.db.api.floating_ip_find"),
            mock.patch("quark.db.api.network_find"),
            mock.patch("quark.db.api.port_find"),
            mock.patch("quark.ipam.QuarkIpam.allocate_ip_address"),
            mock.patch("quark.drivers.unicorn_driver.UnicornDriver"
                       ".register_floating_ip"),
            mock.patch("quark.db.api.port_associate_ip"),
            mock.patch("quark.db.api.floating_ip_associate_fixed_ip"),
            mock.patch("quark.billing.notify"),
            mock.patch("quark.billing.build_payload")
        ) as (flip_find, net_find, port_find, alloc_ip, mock_reg_flip,
              port_assoc, fixed_ip_assoc, notify, build_payload):
            flip_find.return_value = flip_model
            net_find.return_value = net_model
            port_find.return_value = port_model
            alloc_ip.side_effect = _alloc_ip
            port_assoc.side_effect = _port_assoc
            fixed_ip_assoc.side_effect = _flip_fixed_ip_assoc
            build_payload.return_value = {}
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
            with self.assertRaises(ex.BadRequest):
                request = dict(port_id=2, floating_ip_address="10.0.0.1")
                self.plugin.create_floatingip(self.context,
                                              dict(floatingip=request))

    def test_create_with_invalid_network_fails(self):
        with self._stubs():
            with self.assertRaises(ex.NetworkNotFound):
                request = dict(floating_network_id=123,
                               port_id=2, floating_ip_address="10.0.0.1")
                self.plugin.create_floatingip(self.context,
                                              dict(floatingip=request))

    def test_create_with_invalid_port_fails(self):
        network = dict(id="00000000-0000-0000-0000-000000000000",
                       ipam_strategy="ANY")

        with self._stubs(network=network):
            with self.assertRaises(ex.PortNotFound):
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
                    q_ex.FixedIpDoesNotExistsForPort):
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
                    q_ex.PortAlreadyContainsFloatingIp):
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
                    q_ex.NoAvailableFixedIpsForPort):
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
                    q_ex.NoAvailableFixedIpsForPort):
                request = dict(floating_network_id=network["id"],
                               port_id=port["id"])
                self.plugin.create_floatingip(self.context,
                                              dict(floatingip=request))


class TestUpdateFloatingIPs(test_quark_plugin.TestQuarkPlugin):

    def setUp(self):
        super(TestUpdateFloatingIPs, self).setUp()
        # NOTE(blogan): yuck yuck yuck, but since the models are being mocked
        # and not attached to the session, the refresh call will fail.
        old_refresh = self.context.session.refresh

        def reset_refresh(context):
            context.session.refresh = old_refresh

        self.context.session.refresh = mock.Mock()
        self.addCleanup(reset_refresh, self.context)

    @contextlib.contextmanager
    def _stubs(self, flip=None, curr_port=None, new_port=None, ips=None):
        curr_port_model = None
        if curr_port:
            curr_port_model = models.Port()
            curr_port_model.update(curr_port)

        new_port_model = None
        if new_port:
            new_port_model = models.Port()
            new_port_model.update(new_port)
            if ips:
                for ip in ips:
                    ip_model = models.IPAddress()
                    ip_model.update(ip)
                    addr_type = ip.get("address_type")
                    if addr_type == "floating" and "fixed_ip_addr" in ip:
                        fixed_ip = models.IPAddress()
                        fixed_ip.update(next(ip_addr for ip_addr in ips
                                             if (ip_addr["address_readable"] ==
                                                 ip["fixed_ip_addr"])))
                        ip_model.fixed_ip = fixed_ip
                    new_port_model.ip_addresses.append(ip_model)

        flip_model = None
        if flip:
            flip_model = models.IPAddress()
            flip_model.update(flip)
            if curr_port_model:
                flip_model.ports = [curr_port_model]
            fixed_ip = flip.get("fixed_ip_address")
            if fixed_ip:
                addr = netaddr.IPAddress(fixed_ip)
                fixed_ip_model = models.IPAddress()
                fixed_ip_model.update(dict(address_readable=fixed_ip,
                                           address=int(addr), version=4,
                                           address_type="fixed"))
                flip_model.fixed_ip = fixed_ip_model

        def _find_port(context, id, **kwargs):
            return (curr_port_model if (curr_port_model and
                                        id == curr_port_model.id)
                    else new_port_model)

        def _flip_assoc(context, addr, fixed_ip):
            addr.fixed_ips.append(fixed_ip)
            return addr

        def _flip_disassoc(context, addr):
            addr.fixed_ip = None
            return addr

        def _port_assoc(context, ports, addr, enable_ports=None):
            addr.ports = ports
            return addr

        def _port_dessoc(context, ports, addr):
            addr.associations = []
            addr.ports = []
            return addr

        def mock_notify(context, notif_type, flip):
            """We don't want to notify from tests"""
            pass

        with contextlib.nested(
            mock.patch("quark.db.api.floating_ip_find"),
            mock.patch("quark.db.api.port_find"),
            mock.patch("quark.drivers.unicorn_driver.UnicornDriver"
                       ".register_floating_ip"),
            mock.patch("quark.drivers.unicorn_driver.UnicornDriver"
                       ".update_floating_ip"),
            mock.patch("quark.drivers.unicorn_driver.UnicornDriver"
                       ".remove_floating_ip"),
            mock.patch("quark.db.api.port_associate_ip"),
            mock.patch("quark.db.api.port_disassociate_ip"),
            mock.patch("quark.db.api.floating_ip_associate_fixed_ip"),
            mock.patch("quark.db.api.floating_ip_disassociate_fixed_ip"),
            mock.patch("quark.billing.notify")
        ) as (flip_find, port_find, reg_flip, update_flip, rem_flip,
              port_assoc, port_dessoc, flip_assoc, flip_dessoc, notify):
            flip_find.return_value = flip_model
            port_find.side_effect = _find_port
            port_assoc.side_effect = _port_assoc
            port_dessoc.side_effect = _port_dessoc
            flip_assoc.side_effect = _flip_assoc
            flip_dessoc.side_effect = _flip_disassoc
            notify.side_effect = mock_notify
            # We'll yield a notify to check how many times and with which
            # arguments it was called.
            yield notify

    def test_update_with_new_port_and_no_previous_port(self):
        new_port = dict(id="2")

        fixed_ip_addr = netaddr.IPAddress("192.168.0.1")
        fixed_ip = dict(address_type="fixed", version=4,
                        address=int(fixed_ip_addr),
                        address_readable=str(fixed_ip_addr),
                        allocated_at=datetime.datetime.now())

        ips = [fixed_ip]

        addr = netaddr.IPAddress("10.0.0.1")
        flip = dict(id="3", fixed_ip_address="172.16.1.1", address=int(addr),
                    address_readable=str(addr))

        with self._stubs(flip=flip, new_port=new_port, ips=ips) as notify:
            content = dict(port_id=new_port["id"])
            ret = self.plugin.update_floatingip(self.context, flip["id"],
                                                dict(floatingip=content))
            self.assertEqual(ret["fixed_ip_address"], "192.168.0.1")
            self.assertEqual(ret["port_id"], new_port["id"])
            notify.assert_called_once_with(self.context, 'ip.associate',
                                           mock.ANY)

    def test_update_with_new_port(self):
        curr_port = dict(id="1")
        new_port = dict(id="2")
        fixed_ip_addr = netaddr.IPAddress("192.168.0.1")
        fixed_ip = dict(address_type="fixed", version=4,
                        address=int(fixed_ip_addr),
                        address_readable=str(fixed_ip_addr),
                        allocated_at=datetime.datetime.now())

        ips = [fixed_ip]

        addr = netaddr.IPAddress("10.0.0.1")
        flip = dict(id="3", fixed_ip_address="172.16.1.1", address=int(addr),
                    address_readable=str(addr))

        with self._stubs(flip=flip, curr_port=curr_port,
                         new_port=new_port, ips=ips) as notify:
            content = dict(port_id=new_port["id"])
            ret = self.plugin.update_floatingip(self.context, flip["id"],
                                                dict(floatingip=content))
            self.assertEqual(ret["fixed_ip_address"], "192.168.0.1")
            self.assertEqual(ret["port_id"], new_port["id"])
            self.assertEqual(notify.call_count, 2, 'Should notify twice here')
            call_list = [mock.call(self.context, 'ip.disassociate', mock.ANY),
                         mock.call(self.context, 'ip.associate', mock.ANY)]
            notify.assert_has_calls(call_list, any_order=True)

    def test_update_with_no_port(self):
        curr_port = dict(id="1")
        addr = netaddr.IPAddress("10.0.0.1")
        flip = dict(id="3", fixed_ip_address="172.16.1.1", address=int(addr),
                    address_readable=str(addr))

        with self._stubs(flip=flip, curr_port=curr_port) as notify:
            content = dict(port_id=None)
            ret = self.plugin.update_floatingip(self.context, flip["id"],
                                                dict(floatingip=content))
            self.assertEqual(ret.get("fixed_ip_address"), None)
            self.assertEqual(ret.get("port_id"), None)
            notify.assert_called_once_with(self.context, 'ip.disassociate',
                                           mock.ANY)

    def test_update_with_non_existent_port_should_fail(self):
        addr = netaddr.IPAddress("10.0.0.1")
        flip = dict(id="3", fixed_ip_address="172.16.1.1", address=int(addr),
                    address_readable=str(addr))

        with self._stubs(flip=flip):
            with self.assertRaises(ex.PortNotFound):
                content = dict(port_id="123")
                self.plugin.update_floatingip(self.context, flip["id"],
                                              dict(floatingip=content))

    def test_update_with_port_with_no_fixed_ip_avail_should_fail(self):
        new_port = dict(id="123")
        addr = netaddr.IPAddress("10.0.0.1")
        flip = dict(id="3", fixed_ip_address="172.16.1.1", address=int(addr),
                    address_readable=str(addr))

        with self._stubs(flip=flip, new_port=new_port):
            with self.assertRaises(q_ex.NoAvailableFixedIpsForPort):
                content = dict(port_id="123")
                self.plugin.update_floatingip(self.context, flip["id"],
                                              dict(floatingip=content))

    def test_update_with_same_port_should_fail(self):
        new_port = dict(id="123")
        curr_port = dict(id="123")
        addr = netaddr.IPAddress("10.0.0.1")
        flip = dict(id="3", fixed_ip_address="172.16.1.1", address=int(addr),
                    address_readable=str(addr))

        with self._stubs(flip=flip, new_port=new_port, curr_port=curr_port):
            with self.assertRaises(q_ex.PortAlreadyAssociatedToFloatingIp):
                content = dict(port_id="123")
                self.plugin.update_floatingip(self.context, flip["id"],
                                              dict(floatingip=content))

    def test_update_when_port_has_a_different_flip_should_fail(self):
        new_port = dict(id="123")
        floating_ip_addr = netaddr.IPAddress("192.168.0.1")
        floating_ip = dict(address_type="floating", version=4,
                           address=int(floating_ip_addr),
                           address_readable=str(floating_ip_addr),
                           allocated_at=datetime.datetime.now())

        ips = [floating_ip]

        curr_port = dict(id="456")
        addr = netaddr.IPAddress("10.0.0.1")
        flip = dict(id="3", fixed_ip_address="172.16.1.1", address=int(addr),
                    address_readable=str(addr))

        with self._stubs(flip=flip, new_port=new_port,
                         curr_port=curr_port, ips=ips):
            with self.assertRaises(q_ex.PortAlreadyContainsFloatingIp):
                content = dict(port_id="123")
                self.plugin.update_floatingip(self.context, flip["id"],
                                              dict(floatingip=content))

    def test_update_with_no_port_and_no_previous_port_should_fail(self):
        addr = netaddr.IPAddress("10.0.0.1")
        flip = dict(id="3", fixed_ip_address="172.16.1.1", address=int(addr),
                    address_readable=str(addr))

        with self._stubs(flip=flip):
            with self.assertRaises(q_ex.FloatingIpUpdateNoPortIdSupplied):
                content = dict(port_id=None)
                self.plugin.update_floatingip(self.context, flip["id"],
                                              dict(floatingip=content))

    def test_update_with_missing_port_id_param_should_fail(self):
        with self._stubs():
            with self.assertRaises(ex.BadRequest):
                content = {}
                self.plugin.update_floatingip(self.context, "123",
                                              dict(floatingip=content))
