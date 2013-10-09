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
from neutron.openstack.common.notifier import api as notifier_api
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
        self.ipam = quark.ipam.QuarkIpamANY()

        class FakeContext(object):
            def __new__(cls, *args, **kwargs):
                return super(FakeContext, cls).__new__(cls)

            def __enter__(*args, **kwargs):
                pass

            def __exit__(*args, **kwargs):
                pass

        self.context.session.begin = FakeContext
        self.context.session.add = mock.Mock()

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
        port = dict(ip_addresses=[], device_id="foo")
        addr = dict(ports=[port], tenant_id=1, subnet_id=1,
                    address_readable=None, created_at=None)
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


class QuarkIpamTestBothIpAllocation(QuarkIpamBaseTest):
    def setUp(self):
        super(QuarkIpamTestBothIpAllocation, self).setUp()
        self.ipam = quark.ipam.QuarkIpamBOTH()
        self.v6_fip = 338854485284841385865528720941232685056L
        self.v6_lip = 338854485284841385865528720941249462271L

    @contextlib.contextmanager
    def _stubs(self, addresses=None, subnets=None):
        if not addresses:
            addresses = [None, None]
        db_mod = "quark.db.api"
        self.context.session.add = mock.Mock()
        with contextlib.nested(
            mock.patch("%s.ip_address_find" % db_mod),
            mock.patch("%s.subnet_find_allocation_counts" % db_mod)
        ) as (addr_find, subnet_find):
            addr_find.side_effect = addresses
            subnet_find.side_effect = subnets
            yield

    def test_allocate_new_ip_address_two_empty_subnets(self):
        subnet4 = dict(id=1, first_ip=0, last_ip=255,
                       cidr="0.0.0.0/24", ip_version=4,
                       next_auto_assign_ip=0, network=dict(ip_policy=None),
                       ip_policy=None)
        subnet6 = dict(id=1, first_ip=self.v6_fip, last_ip=self.v6_lip,
                       cidr="feed::/104", ip_version=6,
                       next_auto_assign_ip=0, network=dict(ip_policy=None),
                       ip_policy=None)
        with self._stubs(subnets=[[(subnet4, 0)], [(subnet6, 0)]],
                         addresses=[None, None, None, None]):
            address = self.ipam.allocate_ip_address(self.context, 0, 0, 0)
            self.assertEqual(address[0]["address"], 2)
            self.assertEqual(address[1]["address"], 0)

    def test_allocate_new_ip_address_one_v4_subnet_open(self):
        subnet4 = dict(id=1, first_ip=0, last_ip=255,
                       cidr="0.0.0.0/24", ip_version=4,
                       next_auto_assign_ip=0, network=dict(ip_policy=None),
                       ip_policy=None)
        with self._stubs(subnets=[[(subnet4, 0)], []],
                         addresses=[None, None, None, None]):
            address = self.ipam.allocate_ip_address(self.context, 0, 0, 0)
            self.assertEqual(len(address), 1)
            self.assertEqual(address[0]["version"], 4)

    def test_allocate_new_ip_address_one_v6_subnet_open(self):
        subnet6 = dict(id=1, first_ip=self.v6_fip, last_ip=self.v6_lip,
                       cidr="feed::/104", ip_version=6,
                       next_auto_assign_ip=0, network=dict(ip_policy=None),
                       ip_policy=None)
        with self._stubs(subnets=[[], [(subnet6, 0)]],
                         addresses=[None, None, None, None]):
            address = self.ipam.allocate_ip_address(self.context, 0, 0, 0)
            self.assertEqual(len(address), 1)
            self.assertEqual(address[0]["version"], 6)

    def test_allocate_new_ip_address_no_avail_subnets(self):
        with self._stubs(subnets=[[], []],
                         addresses=[None, None, None, None]):
            with self.assertRaises(exceptions.IpAddressGenerationFailure):
                self.ipam.allocate_ip_address(self.context, 0, 0, 0)

    def test_reallocate_deallocated_v4_ip(self):
        subnet6 = dict(id=1, first_ip=self.v6_fip, last_ip=self.v6_lip,
                       cidr="feed::/104", ip_version=6,
                       next_auto_assign_ip=0, network=dict(ip_policy=None),
                       ip_policy=None)
        address = models.IPAddress()
        address["address"] = 4
        address["version"] = 4
        address["subnet"] = models.Subnet(cidr="0.0.0.0/24")
        with self._stubs(subnets=[[(subnet6, 0)]],
                         addresses=[address, None, None]):
            address = self.ipam.allocate_ip_address(self.context, 0, 0, 0)
            self.assertEqual(len(address), 2)
            self.assertEqual(address[0]["address"], 4)
            self.assertEqual(address[0]["version"], 4)
            self.assertEqual(address[1]["address"], 0)
            self.assertEqual(address[1]["version"], 6)

    def test_reallocate_deallocated_v4_ip_no_avail_subnets(self):
        address = models.IPAddress()
        address["address"] = 4
        address["version"] = 4
        address["subnet"] = models.Subnet(cidr="0.0.0.0/24")
        with self._stubs(subnets=[[]],
                         addresses=[address, None, None]):
            address = self.ipam.allocate_ip_address(self.context, 0, 0, 0)
            self.assertEqual(len(address), 1)
            self.assertEqual(address[0]["address"], 4)
            self.assertEqual(address[0]["version"], 4)

    def test_reallocate_deallocated_v6_ip(self):
        subnet4 = dict(id=1, first_ip=0, last_ip=255,
                       cidr="0.0.0.0/24", ip_version=4,
                       next_auto_assign_ip=0, network=dict(ip_policy=None),
                       ip_policy=None)
        address = models.IPAddress()
        address["address"] = 4
        address["version"] = 6
        address["subnet"] = models.Subnet(cidr="::/120")
        with self._stubs(subnets=[[(subnet4, 0)]],
                         addresses=[address, None, None]):
            address = self.ipam.allocate_ip_address(self.context, 0, 0, 0)
            self.assertEqual(len(address), 2)
            self.assertEqual(address[0]["address"], 4)
            self.assertEqual(address[0]["version"], 6)
            self.assertEqual(address[1]["address"], 2)
            self.assertEqual(address[1]["version"], 4)

    def test_reallocate_deallocated_v4_v6(self):
        address1 = models.IPAddress()
        address1["address"] = 4
        address1["version"] = 4
        address1["subnet"] = models.Subnet(cidr="0.0.0.0/24")
        address2 = models.IPAddress()
        address2["address"] = 42
        address2["version"] = 6
        address2["subnet"] = models.Subnet(cidr="0::/120")
        with self._stubs(subnets=[[]],
                         addresses=[address1, address2]):
            address = self.ipam.allocate_ip_address(self.context, 0, 0, 0)
            self.assertEqual(len(address), 2)
            self.assertEqual(address[0]["address"], 4)
            self.assertEqual(address[0]["version"], 4)
            self.assertEqual(address[1]["address"], 42)
            self.assertEqual(address[1]["version"], 6)


class QuarkIpamTestBothRequiredIpAllocation(QuarkIpamBaseTest):
    def setUp(self):
        super(QuarkIpamTestBothRequiredIpAllocation, self).setUp()
        self.ipam = quark.ipam.QuarkIpamBOTHREQ()
        self.v6_fip = 338854485284841385865528720941232685056L
        self.v6_lip = 338854485284841385865528720941249462271L

    @contextlib.contextmanager
    def _stubs(self, addresses=None, subnets=None):
        if not addresses:
            addresses = [None, None]
        db_mod = "quark.db.api"
        self.context.session.add = mock.Mock()
        with contextlib.nested(
            mock.patch("%s.ip_address_find" % db_mod),
            mock.patch("%s.subnet_find_allocation_counts" % db_mod)
        ) as (addr_find, subnet_find):
            addr_find.side_effect = addresses
            subnet_find.side_effect = subnets
            yield

    def test_allocate_new_ip_address_two_empty_subnets(self):
        subnet4 = dict(id=1, first_ip=0, last_ip=255,
                       cidr="0.0.0.0/24", ip_version=4,
                       next_auto_assign_ip=0, network=dict(ip_policy=None),
                       ip_policy=None)
        subnet6 = dict(id=1, first_ip=self.v6_fip, last_ip=self.v6_lip,
                       cidr="feed::/104", ip_version=6,
                       next_auto_assign_ip=0, network=dict(ip_policy=None),
                       ip_policy=None)
        with self._stubs(subnets=[[(subnet4, 0)], [(subnet6, 0)]],
                         addresses=[None, None, None, None]):
            address = self.ipam.allocate_ip_address(self.context, 0, 0, 0)
            self.assertEqual(address[0]["address"], 2)
            self.assertEqual(address[1]["address"], 0)

    def test_allocate_new_ip_address_one_v4_subnet_open(self):
        subnet4 = dict(id=1, first_ip=0, last_ip=255,
                       cidr="0.0.0.0/24", ip_version=4,
                       next_auto_assign_ip=0, network=dict(ip_policy=None),
                       ip_policy=None)
        with self._stubs(subnets=[[(subnet4, 0)], []],
                         addresses=[None, None, None, None]):
            with self.assertRaises(exceptions.IpAddressGenerationFailure):
                self.ipam.allocate_ip_address(self.context, 0, 0, 0)

    def test_allocate_new_ip_address_one_v6_subnet_open(self):
        subnet6 = dict(id=1, first_ip=self.v6_fip, last_ip=self.v6_lip,
                       cidr="feed::/104", ip_version=6,
                       next_auto_assign_ip=0, network=dict(ip_policy=None),
                       ip_policy=None)
        with self._stubs(subnets=[[], [(subnet6, 0)]],
                         addresses=[None, None, None, None]):
            with self.assertRaises(exceptions.IpAddressGenerationFailure):
                self.ipam.allocate_ip_address(self.context, 0, 0, 0)

    def test_allocate_new_ip_address_no_avail_subnets(self):
        with self._stubs(subnets=[[], []],
                         addresses=[None, None, None, None]):
            with self.assertRaises(exceptions.IpAddressGenerationFailure):
                self.ipam.allocate_ip_address(self.context, 0, 0, 0)

    def test_reallocate_deallocated_v4_ip(self):
        subnet6 = dict(id=1, first_ip=self.v6_fip, last_ip=self.v6_lip,
                       cidr="feed::/104", ip_version=6,
                       next_auto_assign_ip=0, network=dict(ip_policy=None),
                       ip_policy=None)
        address = models.IPAddress()
        address["address"] = 4
        address["version"] = 4
        address["subnet"] = models.Subnet(cidr="0.0.0.0/24")
        with self._stubs(subnets=[[(subnet6, 0)]],
                         addresses=[address, None, None]):
            address = self.ipam.allocate_ip_address(self.context, 0, 0, 0)
            self.assertEqual(len(address), 2)
            self.assertEqual(address[0]["address"], 4)
            self.assertEqual(address[0]["version"], 4)
            self.assertEqual(address[1]["address"], 0)
            self.assertEqual(address[1]["version"], 6)

    def test_reallocate_deallocated_v6_ip(self):
        subnet4 = dict(id=1, first_ip=0, last_ip=255,
                       cidr="0.0.0.0/24", ip_version=4,
                       next_auto_assign_ip=0, network=dict(ip_policy=None),
                       ip_policy=None)
        address = models.IPAddress()
        address["address"] = 4
        address["version"] = 6
        address["subnet"] = models.Subnet(cidr="::/120")
        with self._stubs(subnets=[[(subnet4, 0)]],
                         addresses=[address, None, None]):
            address = self.ipam.allocate_ip_address(self.context, 0, 0, 0)
            self.assertEqual(len(address), 2)
            self.assertEqual(address[0]["address"], 4)
            self.assertEqual(address[0]["version"], 6)
            self.assertEqual(address[1]["address"], 2)
            self.assertEqual(address[1]["version"], 4)

    def test_reallocate_deallocated_v4_v6(self):
        address1 = models.IPAddress()
        address1["address"] = 4
        address1["version"] = 4
        address1["subnet"] = models.Subnet(cidr="0.0.0.0/24")
        address2 = models.IPAddress()
        address2["address"] = 42
        address2["version"] = 6
        address2["subnet"] = models.Subnet(cidr="0::/120")
        with self._stubs(subnets=[[]],
                         addresses=[address1, address2]):
            address = self.ipam.allocate_ip_address(self.context, 0, 0, 0)
            self.assertEqual(len(address), 2)
            self.assertEqual(address[0]["address"], 4)
            self.assertEqual(address[0]["version"], 4)
            self.assertEqual(address[1]["address"], 42)
            self.assertEqual(address[1]["version"], 6)


class QuarkIpamBoth(QuarkIpamBaseTest):
    def setUp(self):
        super(QuarkIpamBoth, self).setUp()
        self.ipam = quark.ipam.QuarkIpamBOTH()
        self.v4 = models.IPAddress()
        self.v4["version"] = 4
        self.v6 = models.IPAddress()
        self.v6["version"] = 6

    def test_is_strategy_satisfied_v4_only_fails(self):
        self.assertFalse(self.ipam.is_strategy_satisfied([self.v4, None]))

    def test_is_strategy_satisfied_v6_only_fails(self):
        self.assertFalse(self.ipam.is_strategy_satisfied([None, self.v6]))

    def test_is_strategy_satisfied_none_fails(self):
        self.assertFalse(self.ipam.is_strategy_satisfied([None, None]))

    def test_is_strategy_satisfied_both_passes(self):
        self.assertTrue(self.ipam.is_strategy_satisfied([self.v4, self.v6]))


class QuarkIpamBothRequired(QuarkIpamBaseTest):
    def setUp(self):
        super(QuarkIpamBothRequired, self).setUp()
        self.ipam = quark.ipam.QuarkIpamBOTHREQ()
        self.v4 = models.IPAddress()
        self.v4["version"] = 4
        self.v6 = models.IPAddress()
        self.v6["version"] = 6

    def test_is_strategy_satisfied_v4_only_fails(self):
        self.assertFalse(self.ipam.is_strategy_satisfied([self.v4, None]))

    def test_is_strategy_satisfied_v6_only_fails(self):
        self.assertFalse(self.ipam.is_strategy_satisfied([None, self.v6]))

    def test_is_strategy_satisfied_none_fails(self):
        self.assertFalse(self.ipam.is_strategy_satisfied([None, None]))

    def test_is_strategy_satisfied_both_passes(self):
        self.assertTrue(self.ipam.is_strategy_satisfied([self.v4, self.v6]))


class QuarkNewIPAddressAllocation(QuarkIpamBaseTest):
    @contextlib.contextmanager
    def _stubs(self, addresses=None, subnets=None):
        if not addresses:
            addresses = [None]
        db_mod = "quark.db.api"
        self.context.session.add = mock.Mock()
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
            self.assertEqual(address[0]["address"], 2)  # 0 => 2

    def test_allocate_new_ip_in_partially_allocated_range(self):
        addr = dict(id=1, address=3)
        subnet = dict(id=1, first_ip=0, last_ip=255,
                      cidr="0.0.0.0/24", ip_version=4,
                      next_auto_assign_ip=2, network=dict(ip_policy=None),
                      ip_policy=None)
        with self._stubs(subnets=[(subnet, 0)], addresses=[None, addr, None]):
            address = self.ipam.allocate_ip_address(self.context, 0, 0, 0)
            self.assertEqual(address[0]["address"], 3)

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
            self.assertEqual(address[0]["address"], 258)  # 256 => 258
            self.assertEqual(address[0]["subnet_id"], 2)

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
            self.assertEqual(address[0]["address"], 2)  # 0 => 2
            self.assertEqual(address[0]["subnet_id"], 1)

    def test_find_requested_ip_subnet(self):
        subnet1 = dict(id=1, first_ip=0, last_ip=255,
                       cidr="0.0.0.0/24", ip_version=4,
                       network=dict(ip_policy=None),
                       ip_policy=None)
        subnets = [(subnet1, 1)]
        with self._stubs(subnets=subnets, addresses=[None, None]):
            address = self.ipam.allocate_ip_address(
                self.context, 0, 0, 0, ip_address="0.0.0.240")
            self.assertEqual(address[0]["address"], 240)
            self.assertEqual(address[0]["subnet_id"], 1)

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
    def _stubs(self, ip_find, subnet, address, addresses_found,
               sub_found=True):
        db_mod = "quark.db.api"
        with contextlib.nested(
            mock.patch("%s.ip_address_find" % db_mod),
            mock.patch("%s.ip_address_update" % db_mod),
            mock.patch("quark.ipam.QuarkIpamANY._choose_available_subnet")
        ) as (addr_find, addr_update, choose_subnet):
            if ip_find:
                addr_find.return_value = address
            else:
                address["id"] = None
                addr_find.side_effect = addresses_found
                addr_update.return_value = address
            choose_subnet.return_value = [subnet]
            if not sub_found:
                choose_subnet.return_value = []
            yield choose_subnet

    def test_allocate_finds_deallocated_ip_succeeds(self):
        subnet = dict(id=1, ip_version=4, next_auto_assign_ip=0,
                      cidr="0.0.0.0/24")
        address = dict(id=1, address=0, subnet=subnet)
        addresses_found = [None, address, None]
        with self._stubs(
            True, subnet, address, addresses_found
        ) as (choose_subnet):
            ipaddress = self.ipam.allocate_ip_address(self.context, 0, 0, 0)
            self.assertIsNotNone(ipaddress[0]['id'])
            self.assertFalse(choose_subnet.called)

    def test_allocate_finds_deallocated_ip_out_of_range_deletes(self):
        subnet = dict(id=1, ip_version=4, next_auto_assign_ip=0,
                      cidr="0.0.0.0/29")
        address = dict(id=1, address=254)
        address["subnet"] = subnet
        addresses_found = [address, None]
        self.context.session.delete = mock.Mock()
        with self._stubs(False, subnet, address, addresses_found,
                         sub_found=False):
            addr = self.ipam.allocate_ip_address(self.context, 0, 0, 0)
            self.assertTrue(self.context.session.delete.called)
            self.assertEqual(len(addr), 0)
        self.context.session.delete = mock.Mock()

    def test_allocate_finds_no_deallocated_creates_new_ip(self):
        subnet = dict(id=1, ip_version=4, next_auto_assign_ip=0,
                      cidr="0.0.0.0/24", first_ip=0, last_ip=255,
                      ip_policy=None, network=dict(ip_policy=None))
        address = dict(id=1, address=0)
        addresses_found = [None, address, None]
        with self._stubs(
            False, subnet, address, addresses_found
        ) as (choose_subnet):
            ipaddress = self.ipam.allocate_ip_address(self.context, 0, 0, 0)
            self.assertIsNotNone(ipaddress[0]['id'])
            self.assertTrue(choose_subnet.called)

    def test_allocate_finds_gap_in_address_space(self):
        network_mod = models.Network()
        network_mod.update(dict(ip_policy=None))
        subnet = dict(id=1, ip_version=4, next_auto_assign_ip=0,
                      cidr="0.0.0.0/24", first_ip=0, last_ip=255,
                      network=network_mod, ip_policy=None)
        address0 = dict(id=1, address=0)
        addresses_found = [None, None]
        subnet_mod = models.Subnet()
        subnet_mod.update(subnet)
        with self._stubs(
            False, subnet_mod, address0, addresses_found
        ) as (choose_subnet):
            ipaddress = self.ipam.allocate_ip_address(self.context, 0, 0, 0)
            self.assertEqual(ipaddress[0]["address"], 2)
            self.assertIsNotNone(ipaddress[0]['id'])
            self.assertTrue(choose_subnet.called)


class TestQuarkIpPoliciesIpAllocation(QuarkIpamBaseTest):
    @contextlib.contextmanager
    def _stubs(self, addresses=None, subnets=None):
        if not addresses:
            addresses = [None]
        db_mod = "quark.db.api"
        self.context.session.add = mock.Mock()
        with contextlib.nested(
            mock.patch("%s.ip_address_find" % db_mod),
            mock.patch("%s.subnet_find_allocation_counts" % db_mod)
        ) as (addr_find, subnet_find):
            addr_find.side_effect = addresses
            subnet_find.return_value = subnets
            yield

    def test_default_ip_policy_on_subnet(self):
        subnet = dict(id=1, first_ip=0, last_ip=255,
                      cidr="0.0.0.0/24", ip_version=4,
                      next_auto_assign_ip=0, network=dict(ip_policy=None),
                      ip_policy=dict(models.IPPolicy.DEFAULT_POLICY.policy))
        with self._stubs(subnets=[(subnet, 0)], addresses=[None, None]):
            address = self.ipam.allocate_ip_address(self.context, 0, 0, 0,
                                                    version=4)
            self.assertEqual(address[0]["address"], 2)

    def test_subnet_full_based_on_ip_policy(self):
        subnet = dict(id=1, first_ip=0, last_ip=255,
                      cidr="0.0.0.0/24", ip_version=4,
                      next_auto_assign_ip=0, network=dict(ip_policy=None),
                      ip_policy=dict(exclude=
                                     [dict(offset=0, length=256)]))
        with self._stubs(subnets=[(subnet, 0)], addresses=[None, None]):
            with self.assertRaises(exceptions.IpAddressGenerationFailure):
                self.ipam.allocate_ip_address(self.context, 0, 0, 0, version=4)

    def test_ip_policy_on_subnet(self):
        subnet = dict(id=1, first_ip=0, last_ip=255,
                      cidr="0.0.0.0/24", ip_version=4,
                      next_auto_assign_ip=0, network=dict(ip_policy=None),
                      ip_policy=dict(exclude=
                                     [dict(offset=0, length=2)]))
        with self._stubs(subnets=[(subnet, 0)], addresses=[None, None]):
            address = self.ipam.allocate_ip_address(self.context, 0, 0, 0,
                                                    version=4)
            self.assertEqual(address[0]["address"], 2)

    def test_ip_policy_on_subnet_negative_offset(self):
        subnet = dict(id=1, first_ip=0, last_ip=255,
                      cidr="0.0.0.0/24", ip_version=4,
                      next_auto_assign_ip=0, network=dict(ip_policy=None),
                      ip_policy=dict(exclude=
                                     [dict(offset=-1, length=3)]))
        with self._stubs(subnets=[(subnet, 0)], addresses=[None, None]):
            address = self.ipam.allocate_ip_address(self.context, 0, 0, 0,
                                                    version=4)
            self.assertEqual(address[0]["address"], 2)

    def test_ip_policy_on_network(self):
        net = dict(ip_policy=dict(exclude=
                                  [dict(offset=0, length=2)]))
        subnet = dict(id=1, first_ip=0, last_ip=255,
                      cidr="0.0.0.0/24", ip_version=4,
                      next_auto_assign_ip=0, network=net,
                      ip_policy=None)
        with self._stubs(subnets=[(subnet, 0)], addresses=[None, None]):
            address = self.ipam.allocate_ip_address(self.context, 0, 0, 0,
                                                    version=4)
            self.assertEqual(address[0]["address"], 2)

    def test_ip_policy_on_network_exclusion_intersection(self):
        net = dict(ip_policy=dict(exclude=
                                  [dict(offset=0, length=2),
                                   dict(offset=254, length=1)]))
        subnet = dict(id=1, first_ip=0, last_ip=255,
                      cidr="0.0.0.0/24", ip_version=4,
                      next_auto_assign_ip=0, network=net,
                      ip_policy=None)
        with self._stubs(subnets=[(subnet, 0)], addresses=[None, None]):
            address = self.ipam.allocate_ip_address(self.context, 0, 0, 0,
                                                    version=4)
            self.assertEqual(address[0]["address"], 2)

    def test_ip_policy_on_both_subnet_preferred(self):
        net = dict(ip_policy=dict(exclude=
                                  [dict(offset=0, length=1),
                                   dict(offset=1, length=1)]))
        subnet = dict(id=1, first_ip=0, last_ip=255,
                      cidr="0.0.0.0/24", ip_version=4,
                      next_auto_assign_ip=0, network=net,
                      ip_policy=dict(exclude=
                                     [dict(offset=254, length=1),
                                      dict(offset=255, length=1)]))
        with self._stubs(subnets=[(subnet, 0)], addresses=[None, None]):
            address = self.ipam.allocate_ip_address(self.context, 0, 0, 0,
                                                    version=4)
            self.assertEqual(address[0]["address"], 2)  # 0 => 2

    def test_ip_policy_allows_specified_ip(self):
        subnet1 = dict(id=1, first_ip=0, last_ip=255,
                       cidr="0.0.0.0/24", ip_version=4,
                       network=dict(ip_policy=None),
                       ip_policy=dict(exclude=[dict(offset=240, length=1)]))
        subnets = [(subnet1, 1)]
        with self._stubs(subnets=subnets, addresses=[None, None]):
            address = self.ipam.allocate_ip_address(
                self.context, 0, 0, 0, ip_address="0.0.0.240")
            self.assertEqual(address[0]["address"], 240)


class QuarkIPAddressAllocationNotifications(QuarkIpamBaseTest):
    @contextlib.contextmanager
    def _stubs(self, address, addresses=None, subnets=None, deleted_at=None):

        address = models.IPAddress(**address)
        if not addresses:
            addresses = [None]
        db_mod = "quark.db.api"
        api_mod = "neutron.openstack.common.notifier.api"
        time_mod = "neutron.openstack.common.timeutils"
        with contextlib.nested(
            mock.patch("%s.ip_address_find" % db_mod),
            mock.patch("%s.ip_address_create" % db_mod),
            mock.patch("%s.subnet_find_allocation_counts" % db_mod),
            mock.patch("%s.notify" % api_mod),
            mock.patch("%s.utcnow" % time_mod),
        ) as (addr_find, addr_create, subnet_find, notify, time):
            addr_find.side_effect = addresses
            addr_create.return_value = address
            subnet_find.return_value = subnets
            time.return_value = deleted_at
            yield notify

    def test_allocation_notification(self):
        subnet = dict(id=1, first_ip=0, last_ip=255,
                      cidr="0.0.0.0/24", ip_version=4,
                      next_auto_assign_ip=0, network=dict(ip_policy=None),
                      ip_policy=None)
        address = dict(tenant_id=1, address=0, created_at="123",
                       subnet_id=1, address_readable="0.0.0.0")
        with self._stubs(
            address,
            subnets=[(subnet, 1)],
            addresses=[None, None]
        ) as notify:
            self.ipam.allocate_ip_address(self.context, 0, 0, 0,
                                          version=4)
            notify.assert_called_once_with(
                self.context,
                notifier_api.publisher_id("network"),
                "ip_block.address.create",
                notifier_api.CONF.default_notification_level,
                dict(tenant_id=address["tenant_id"],
                     ip_block_id=address["subnet_id"],
                     ip_address="0.0.0.0",
                     device_ids=[],
                     created_at=address["created_at"]))

    def test_deallocation_notification(self):
        address = dict(tenant_id=1, address=0, created_at="123",
                       subnet_id=1, address_readable="0.0.0.0",
                       ports=[dict(device_id="foo")])
        port = dict(ip_addresses=[address])
        with self._stubs(dict(), deleted_at="456") as notify:
            self.ipam.deallocate_ip_address(self.context, port)
            notify.assert_called_once_with(
                self.context,
                notifier_api.publisher_id("network"),
                "ip_block.address.delete",
                notifier_api.CONF.default_notification_level,
                dict(tenant_id=address["tenant_id"],
                     ip_block_id=address["subnet_id"],
                     ip_address="0.0.0.0",
                     device_ids=["foo"],
                     created_at=address["created_at"],
                     deleted_at="456"))
