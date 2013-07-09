# Copyright (c) 2014 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import contextlib
import mock
from neutron.common import exceptions
from neutron.db import api as neutron_db_api
from neutron.openstack.common.db.sqlalchemy import session as neutron_session
from oslo.config import cfg

from quark.db import models
import quark.ipam

from quark.tests import test_base


class QuarkIpamBaseTest(test_base.TestBase):
    def setUp(self):
        super(QuarkIpamBaseTest, self).setUp()

        cfg.CONF.set_override('connection', 'sqlite://', 'database')
        neutron_db_api.configure_db()
        models.BASEV2.metadata.create_all(neutron_session._ENGINE)
        self.ipam = quark.ipam.QuarkIpam()

    def tearDown(self):
        neutron_db_api.clear_db()


class QuarkMacAddressAllocateDeallocated(QuarkIpamBaseTest):
    @contextlib.contextmanager
    def _stubs(self, mac_find=True):
        address = dict(id=1, address=0)
        mac_range = dict(id=1, first_address=0, last_address=255,
                         next_auto_assign_mac=0)
        db_mod = "quark.db.api"
        with contextlib.nested(
            mock.patch("%s.mac_address_find" % db_mod),
            mock.patch("%s.mac_address_range_find_allocation_counts" % db_mod),
            mock.patch("%s.mac_address_update" % db_mod),
            mock.patch("%s.mac_address_create" % db_mod)
        ) as (addr_find, mac_range_count, mac_update, mac_create):
            if mac_find:
                addr_find.return_value = address
            else:
                addr_find.side_effect = [None, None]
            mac_range_count.return_value = [(mac_range, 0)]
            mac_create.return_value = address
            yield mac_update, mac_create

    def test_allocate_mac_address_find_deallocated(self):
        with self._stubs(True) as (mac_update, mac_create):
            self.ipam.allocate_mac_address(self.context, 0, 0, 0)
            self.assertTrue(mac_update.called)
            self.assertFalse(mac_create.called)

    def test_allocate_mac_address_creates_new_mac(self):
        with self._stubs(False) as (mac_update, mac_create):
            self.ipam.allocate_mac_address(self.context, 0, 0, 0)
            self.assertFalse(mac_update.called)
            self.assertTrue(mac_create.called)


class QuarkNewMacAddressAllocation(QuarkIpamBaseTest):
    @contextlib.contextmanager
    def _stubs(self, addresses=None, ranges=None):
        if not addresses:
            addresses = [None]
        db_mod = "quark.db.api"
        with contextlib.nested(
            mock.patch("%s.mac_address_find" % db_mod),
            mock.patch("%s.mac_address_range_find_allocation_counts" % db_mod),
        ) as (mac_find, mac_range_count):
            mac_find.side_effect = addresses
            mac_range_count.return_value = ranges
            yield

    def test_allocate_new_mac_address_specific(self):
        mar = dict(id=1, first_address=0, last_address=255,
                   next_auto_assign_mac=0)
        with self._stubs(ranges=[(mar, 0)], addresses=[None, None]):
            address = self.ipam.allocate_mac_address(self.context, 0, 0, 0,
                                                     mac_address=254)
            self.assertEqual(address["address"], 254)

    def test_allocate_new_mac_address_in_empty_range(self):
        mar = dict(id=1, first_address=0, last_address=255,
                   next_auto_assign_mac=0)
        with self._stubs(ranges=[(mar, 0)], addresses=[None, None]):
            address = self.ipam.allocate_mac_address(self.context, 0, 0, 0)
            self.assertEqual(address["address"], 0)

    def test_allocate_new_mac_in_partially_allocated_range(self):
        mar = dict(id=1, first_address=0, last_address=255,
                   next_auto_assign_mac=1)
        with self._stubs(ranges=[(mar, 0)], addresses=[None, None]):
            address = self.ipam.allocate_mac_address(self.context, 0, 0, 0)
            self.assertEqual(address["address"], 1)

    def test_allocate_mac_one_full_one_open_range(self):
        mar1 = dict(id=1, first_address=0, last_address=1,
                    next_auto_assign_mac=0)
        mar2 = dict(id=2, first_address=2, last_address=255,
                    next_auto_assign_mac=2)
        ranges = [(mar1, 1), (mar2, 0)]
        with self._stubs(ranges=ranges, addresses=[None, None]):
            address = self.ipam.allocate_mac_address(self.context, 0, 0, 0)
            self.assertEqual(address["mac_address_range_id"], 2)
            self.assertEqual(address["address"], 2)

    def test_allocate_mac_no_ranges_fails(self):
        with self._stubs(ranges=[]):
            with self.assertRaises(exceptions.MacAddressGenerationFailure):
                self.ipam.allocate_mac_address(self.context, 0, 0, 0)

    def test_allocate_mac_no_available_range_fails(self):
        mar = dict(id=1, first_address=0, last_address=0,
                   next_auto_assign_mac=0)
        ranges = [(mar, 0)]
        with self._stubs(ranges=ranges):
            with self.assertRaises(exceptions.MacAddressGenerationFailure):
                self.ipam.allocate_mac_address(self.context, 0, 0, 0)

    def test_allocate_mac_two_open_ranges_chooses_first(self):
        mar1 = dict(id=1, first_address=0, last_address=255,
                    next_auto_assign_mac=0)
        mar2 = dict(id=2, first_address=256, last_address=510,
                    next_auto_assign_mac=256)
        ranges = [(mar1, 0), (mar2, 0)]
        with self._stubs(ranges=ranges, addresses=[None, None]):
            address = self.ipam.allocate_mac_address(self.context, 0, 0, 0)
            self.assertEqual(address["mac_address_range_id"], 1)
            self.assertEqual(address["address"], 0)


class QuarkMacAddressDeallocation(QuarkIpamBaseTest):
    @contextlib.contextmanager
    def _stubs(self, mac):
        with contextlib.nested(
            mock.patch("quark.db.api.mac_address_find"),
            mock.patch("quark.db.api.mac_address_update")
        ) as (mac_find,
              mac_update):
            mac_update.return_value = mac
            mac_find.return_value = mac
            yield mac_update

    def test_deallocate_mac(self):
        mac = dict(id=1, address=1)
        with self._stubs(mac=mac) as mac_update:
            self.ipam.deallocate_mac_address(self.context, mac["address"])
            self.assertTrue(mac_update.called)

    def test_deallocate_mac_mac_not_found_fails(self):
        with self._stubs(mac=None) as mac_update:
            self.assertRaises(exceptions.NotFound,
                              self.ipam.deallocate_mac_address, self.context,
                              0)
            self.assertFalse(mac_update.called)


class QuarkIPAddressDeallocation(QuarkIpamBaseTest):
    def test_deallocate_ip_address(self):
        port = dict(ip_addresses=[])
        addr = dict(ports=[port])
        port["ip_addresses"].append(addr)
        self.ipam.deallocate_ip_address(self.context, port)
        # ORM takes care of other model if one model is modified
        self.assertTrue(len(addr["ports"]) == 0 or
                        len(port["ip_addresses"]) == 0)
        self.assertTrue(addr["deallocated"])

    def test_deallocate_ip_address_multiple_ports_no_deallocation(self):
        port = dict(ip_addresses=[])
        addr = dict(ports=[port, 2], deallocated=False)
        port["ip_addresses"].append(addr)
        self.ipam.deallocate_ip_address(self.context, port)
        # ORM takes care of other model if one model is modified
        self.assertTrue(len(addr["ports"]) == 1 or
                        len(port["ip_addresses"]) == 0)
        self.assertFalse(addr["deallocated"])


class QuarkNewIPAddressAllocation(QuarkIpamBaseTest):
    @contextlib.contextmanager
    def _stubs(self, addresses=None, subnets=None):
        if not addresses:
            addresses = [None]
        db_mod = "quark.db.api"
        with contextlib.nested(
            mock.patch("%s.ip_address_find" % db_mod),
            mock.patch("%s.subnet_find_allocation_counts" % db_mod)
        ) as (addr_find, subnet_find):
            addr_find.side_effect = addresses
            subnet_find.return_value = subnets
            yield

    def test_allocate_new_ip_address_in_empty_range(self):
        subnet = dict(id=1, first_ip=0, last_ip=255,
                      cidr="0.0.0.0/24", ip_version=4,
                      next_auto_assign_ip=0, network=dict(ip_policy=None),
                      ip_policy=None)
        with self._stubs(subnets=[(subnet, 0)], addresses=[None, None]):
            address = self.ipam.allocate_ip_address(self.context, 0, 0, 0,
                                                    version=4)
            self.assertEqual(address["address"], 0)

    def test_allocate_new_ip_in_partially_allocated_range(self):
        addr = dict(id=1, address=3)
        subnet = dict(id=1, first_ip=0, last_ip=255,
                      cidr="0.0.0.0/24", ip_version=4,
                      next_auto_assign_ip=2, network=dict(ip_policy=None),
                      ip_policy=None)
        with self._stubs(subnets=[(subnet, 0)], addresses=[None, addr, None]):
            address = self.ipam.allocate_ip_address(self.context, 0, 0, 0)
            self.assertEqual(address["address"], 3)

    def test_allocate_ip_one_full_one_open_subnet(self):
        subnet1 = dict(id=1, first_ip=0, last_ip=0,
                       cidr="0.0.0.0/32", ip_version=4,
                       next_auto_assign_ip=0, network=dict(ip_policy=None),
                       ip_policy=None)
        subnet2 = dict(id=2, first_ip=256, last_ip=512,
                       cidr="0.0.1.0/24", ip_version=4,
                       next_auto_assign_ip=256, network=dict(ip_policy=None),
                       ip_policy=None)
        subnets = [(subnet1, 1), (subnet2, 0)]
        with self._stubs(subnets=subnets, addresses=[None, None]):
            address = self.ipam.allocate_ip_address(self.context, 0, 0, 0)
            self.assertEqual(address["address"], 256)
            self.assertEqual(address["subnet_id"], 2)

    def test_allocate_ip_no_subnet_fails(self):
        with self._stubs(subnets=[]):
            with self.assertRaises(exceptions.IpAddressGenerationFailure):
                self.ipam.allocate_ip_address(self.context, 0, 0, 0)

    def test_allocate_ip_no_available_subnet_fails(self):
        subnet1 = dict(id=1, first_ip=0, last_ip=0,
                       cidr="0.0.0.0/32", ip_version=4,
                       network=dict(ip_policy=None), ip_policy=None)
        with self._stubs(subnets=[(subnet1, 1)]):
            with self.assertRaises(exceptions.IpAddressGenerationFailure):
                self.ipam.allocate_ip_address(self.context, 0, 0, 0)

    def test_allocate_ip_two_open_subnets_choses_first(self):
        subnet1 = dict(id=1, first_ip=0, last_ip=255,
                       cidr="0.0.0.0/24", ip_version=4,
                       next_auto_assign_ip=0, network=dict(ip_policy=None),
                       ip_policy=None)
        subnet2 = dict(id=2, first_ip=256, last_ip=510,
                       cidr="0.0.1.0/24", ip_version=4,
                       next_auto_assign_ip=0, network=dict(ip_policy=None),
                       ip_policy=None)
        subnets = [(subnet1, 1), (subnet2, 1)]
        with self._stubs(subnets=subnets, addresses=[None, None]):
            address = self.ipam.allocate_ip_address(self.context, 0, 0, 0)
            self.assertEqual(address["address"], 0)
            self.assertEqual(address["subnet_id"], 1)

    def test_find_requested_ip_subnet(self):
        subnet1 = dict(id=1, first_ip=0, last_ip=255,
                       cidr="0.0.0.0/24", ip_version=4,
                       network=dict(ip_policy=None),
                       ip_policy=None)
        subnets = [(subnet1, 1)]
        with self._stubs(subnets=subnets, addresses=[None, None]):
            address = self.ipam.allocate_ip_address(
                self.context, 0, 0, 0, ip_address="0.0.0.240")
            self.assertEqual(address["address"], 240)
            self.assertEqual(address["subnet_id"], 1)

    def test_find_requested_ip_subnet_already_exists_fails(self):
        subnet1 = dict(id=1, first_ip=0, last_ip=255,
                       cidr="0.0.0.0/24", ip_version=4,
                       network=dict(ip_policy=None),
                       ip_policy=None)
        subnets = [(subnet1, 1)]
        with self._stubs(subnets=subnets, addresses=[None, True]):
            with self.assertRaises(exceptions.IpAddressGenerationFailure):
                self.ipam.allocate_ip_address(
                    self.context, 0, 0, 0, ip_address="0.0.0.240")

    def test_no_valid_subnet_for_requested_ip_fails(self):
        subnet1 = dict(id=1, first_ip=0, last_ip=255,
                       cidr="0.0.1.0/24", ip_version=4)
        subnets = [(subnet1, 1)]
        with self._stubs(subnets=subnets, addresses=[None, None]):
            with self.assertRaises(exceptions.IpAddressGenerationFailure):
                self.ipam.allocate_ip_address(
                    self.context, 0, 0, 0, ip_address="0.0.0.240")


class QuarkIPAddressAllocateDeallocated(QuarkIpamBaseTest):
    @contextlib.contextmanager
    def _stubs(self, ip_find, subnet, address, addresses_found):
        db_mod = "quark.db.api"
        with contextlib.nested(
            mock.patch("%s.ip_address_find" % db_mod),
            mock.patch("%s.ip_address_update" % db_mod),
            mock.patch("quark.ipam.QuarkIpam._choose_available_subnet")
        ) as (addr_find, addr_update, choose_subnet):
            if ip_find:
                addr_find.return_value = address
            else:
                address["id"] = None
                addr_find.side_effect = addresses_found
                addr_update.return_value = address
            choose_subnet.return_value = subnet
            yield choose_subnet

    def test_allocate_finds_deallocated_ip_succeeds(self):
        subnet = dict(id=1, ip_version=4, next_auto_assign_ip=0,
                      cidr="0.0.0.0/24")
        address = dict(id=1, address=0)
        addresses_found = [None, address, None]
        with self._stubs(
            True, subnet, address, addresses_found
        ) as (choose_subnet):
            ipaddress = self.ipam.allocate_ip_address(self.context, 0, 0, 0)
            self.assertIsNotNone(ipaddress['id'])
            self.assertFalse(choose_subnet.called)

    def test_allocate_finds_no_deallocated_creates_new_ip(self):
        '''Fails based on the choice of reuse_after argument.

        Allocates new ip address instead of previously deallocated mac
        address.
        '''
        subnet = dict(id=1, ip_version=4, next_auto_assign_ip=0,
                      cidr="0.0.0.0/24", first_ip=0, last_ip=255,
                      ip_policy=None, network=dict(ip_policy=None))
        address = dict(id=1, address=0)
        addresses_found = [None, address, None]
        with self._stubs(
            False, subnet, address, addresses_found
        ) as (choose_subnet):
            ipaddress = self.ipam.allocate_ip_address(self.context, 0, 0, 0)
            self.assertIsNone(ipaddress['id'])
            self.assertTrue(choose_subnet.called)

    def test_allocate_finds_gap_in_address_space(self):
        """Succeeds by looping through a gap in the address space.

        This edge case occurs because users are allowed to select a specific IP
        address to create.
        """
        subnet = dict(id=1, ip_version=4, next_auto_assign_ip=0,
                      cidr="0.0.0.0/24", first_ip=0, last_ip=255,
                      network=dict(ip_policy=None), ip_policy=None)
        address0 = dict(id=1, address=0)
        address1 = dict(id=1, address=1)
        addresses_found = [None, address0, address1, None]
        with self._stubs(
            False, subnet, address0, addresses_found
        ) as (choose_subnet):
            ipaddress = self.ipam.allocate_ip_address(self.context, 0, 0, 0)
            self.assertEqual(ipaddress["address"], 2)
            self.assertIsNone(ipaddress['id'])
            self.assertTrue(choose_subnet.called)


class TestQuarkIpPoliciesIpAllocation(QuarkIpamBaseTest):
    @contextlib.contextmanager
    def _stubs(self, addresses=None, subnets=None):
        if not addresses:
            addresses = [None]
        db_mod = "quark.db.api"
        with contextlib.nested(
            mock.patch("%s.ip_address_find" % db_mod),
            mock.patch("%s.subnet_find_allocation_counts" % db_mod)
        ) as (addr_find, subnet_find):
            addr_find.side_effect = addresses
            subnet_find.return_value = subnets
            yield

    def test_subnet_full_based_on_ip_policy(self):
        subnet = dict(id=1, first_ip=0, last_ip=255,
                      cidr="0.0.0.0/24", ip_version=4,
                      next_auto_assign_ip=0, network=dict(ip_policy=None),
                      ip_policy=dict(exclude=
                                     [dict(address=0, prefix=24)]))
        with self._stubs(subnets=[(subnet, 0)], addresses=[None, None]):
            with self.assertRaises(exceptions.IpAddressGenerationFailure):
                self.ipam.allocate_ip_address(self.context, 0, 0, 0, version=4)

    def test_ip_policy_on_subnet(self):
        subnet = dict(id=1, first_ip=0, last_ip=255,
                      cidr="0.0.0.0/24", ip_version=4,
                      next_auto_assign_ip=0, network=dict(ip_policy=None),
                      ip_policy=dict(exclude=
                                     [dict(address=0, prefix=32),
                                      dict(address=1, prefix=32)]))
        with self._stubs(subnets=[(subnet, 0)], addresses=[None, None]):
            address = self.ipam.allocate_ip_address(self.context, 0, 0, 0,
                                                    version=4)
            self.assertEqual(address["address"], 2)

    def test_ip_policy_on_network(self):
        net = dict(ip_policy=dict(exclude=
                                  [dict(address=0, prefix=32),
                                   dict(address=1, prefix=32)]))
        subnet = dict(id=1, first_ip=0, last_ip=255,
                      cidr="0.0.0.0/24", ip_version=4,
                      next_auto_assign_ip=0, network=net,
                      ip_policy=None)
        with self._stubs(subnets=[(subnet, 0)], addresses=[None, None]):
            address = self.ipam.allocate_ip_address(self.context, 0, 0, 0,
                                                    version=4)
            self.assertEqual(address["address"], 2)

    def test_ip_policy_on_network_exclusion_intersection(self):
        net = dict(ip_policy=dict(exclude=
                                  [dict(address=0, prefix=32),
                                   dict(address=1, prefix=32),
                                   dict(address=254, prefix=32)]))
        subnet = dict(id=1, first_ip=0, last_ip=63,
                      cidr="0.0.0.0/30", ip_version=4,
                      next_auto_assign_ip=0, network=net,
                      ip_policy=None)
        with self._stubs(subnets=[(subnet, 0)], addresses=[None, None]):
            address = self.ipam.allocate_ip_address(self.context, 0, 0, 0,
                                                    version=4)
            self.assertEqual(address["address"], 2)

    def test_ip_policy_on_both_subnet_preferred(self):
        net = dict(ip_policy=dict(exclude=
                                  [dict(address=0, prefix=32),
                                   dict(address=1, prefix=32)]))
        subnet = dict(id=1, first_ip=0, last_ip=255,
                      cidr="0.0.0.0/24", ip_version=4,
                      next_auto_assign_ip=0, network=net,
                      ip_policy=dict(exclude=
                                     [dict(address=254, prefix=32),
                                      dict(address=255, prefix=32)]))
        with self._stubs(subnets=[(subnet, 0)], addresses=[None, None]):
            address = self.ipam.allocate_ip_address(self.context, 0, 0, 0,
                                                    version=4)
            self.assertEqual(address["address"], 0)

    def test_ip_policy_allows_specified_ip(self):
        subnet1 = dict(id=1, first_ip=0, last_ip=255,
                       cidr="0.0.0.0/24", ip_version=4,
                       network=dict(ip_policy=None),
                       ip_policy=dict(exclude=[dict(address=240, prefix=32)]))
        subnets = [(subnet1, 1)]
        with self._stubs(subnets=subnets, addresses=[None, None]):
            address = self.ipam.allocate_ip_address(
                self.context, 0, 0, 0, ip_address="0.0.0.240")
            self.assertEqual(address["address"], 240)
