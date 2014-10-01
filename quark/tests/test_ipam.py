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
import netaddr
from neutron.common import exceptions
from neutron.common import rpc
from oslo.config import cfg
from oslo.db import exception as db_exc

from quark.db import models
from quark import exceptions as q_exc
import quark.ipam
from quark.tests import test_base


class QuarkIpamBaseTest(test_base.TestBase):
    def setUp(self):
        super(QuarkIpamBaseTest, self).setUp()

        patcher = mock.patch("neutron.common.rpc.messaging")
        patcher.start()
        self.addCleanup(patcher.stop)
        rpc.init(mock.MagicMock())

        self.ipam = quark.ipam.QuarkIpamANY()
        self.reuse_after = cfg.CONF.QUARK.ipam_reuse_after

        class FakeContext(object):
            def __enter__(*args, **kwargs):
                pass

            def __exit__(*args, **kwargs):
                pass

        self.context.session.begin = FakeContext
        self.context.session.add = mock.Mock()


class QuarkMacAddressAllocateDeallocated(QuarkIpamBaseTest):
    @contextlib.contextmanager
    def _stubs(self, mac_find=True):
        address = dict(id=1, address=0)
        mac_range = dict(id=1, first_address=0, last_address=255,
                         next_auto_assign_mac=0)
        with contextlib.nested(
            mock.patch("quark.db.api.mac_address_find"),
            mock.patch("quark.db.api."
                       "mac_address_range_find_allocation_counts"),
            mock.patch("quark.db.api.mac_address_update"),
            mock.patch("quark.db.api.mac_address_create")
        ) as (addr_find, mac_range_count, mac_update, mac_create):
            if mac_find:
                addr_find.return_value = address
            else:
                addr_find.side_effect = [None, None]
            mac_range_count.return_value = (mac_range, 0)
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
        with contextlib.nested(
            mock.patch("quark.db.api.mac_address_find"),
            mock.patch("quark.db.api."
                       "mac_address_range_find_allocation_counts"),
        ) as (mac_find, mac_range_count):
            mac_find.side_effect = addresses
            mac_range_count.return_value = ranges
            yield

    def test_allocate_new_mac_address_specific(self):
        mar = dict(id=1, first_address=0, last_address=255,
                   next_auto_assign_mac=0)
        with self._stubs(ranges=(mar, 0), addresses=[None, None]):
            address = self.ipam.allocate_mac_address(self.context, 0, 0, 0,
                                                     mac_address=254)
            self.assertEqual(address["address"], 254)

    def test_allocate_new_mac_address_in_empty_range(self):
        mar = dict(id=1, first_address=0, last_address=255,
                   next_auto_assign_mac=0)
        with self._stubs(ranges=(mar, 0), addresses=[None, None]):
            address = self.ipam.allocate_mac_address(self.context, 0, 0, 0)
            self.assertEqual(address["address"], 0)

    def test_allocate_new_mac_in_partially_allocated_range(self):
        mar = dict(id=1, first_address=0, last_address=255,
                   next_auto_assign_mac=1)
        with self._stubs(ranges=(mar, 0), addresses=[None, None]):
            address = self.ipam.allocate_mac_address(self.context, 0, 0, 0)
            self.assertEqual(address["address"], 1)

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

    def test_allocate_mac_last_mac_in_range_closes_range(self):
        mar = dict(id=1, first_address=0, last_address=1,
                   next_auto_assign_mac=1)
        with self._stubs(ranges=(mar, 0), addresses=[None, None]):
            address = self.ipam.allocate_mac_address(self.context, 0, 0, 0)
            self.assertEqual(address["address"], 1)
            self.assertEqual(mar["next_auto_assign_mac"], -1)

    def test_allocate_mac_range_unexpectedly_filled_closes(self):
        mar = dict(id=1, first_address=0, last_address=1,
                   next_auto_assign_mac=1)
        with self._stubs(ranges=(mar, 4), addresses=[None, None]):
            with self.assertRaises(exceptions.MacAddressGenerationFailure):
                self.ipam.allocate_mac_address(self.context, 0, 0, 0)
            self.assertEqual(mar["next_auto_assign_mac"], -1)


class QuarkNewMacAddressAllocationCreateConflict(QuarkIpamBaseTest):
    @contextlib.contextmanager
    def _stubs(self, addresses=None, ranges=None):
        if not addresses:
            addresses = [None]
        with contextlib.nested(
            mock.patch("quark.db.api.mac_address_find"),
            mock.patch("quark.db.api.mac_address_create"),
            mock.patch("quark.db.api."
                       "mac_address_range_find_allocation_counts"),
        ) as (mac_find, mac_create, mac_range_count):
            mac_find.side_effect = [None, None]
            mac_create.side_effect = addresses
            mac_range_count.return_value = ranges
            yield

    def test_allocate_existing_mac_fails_and_retries(self):
        mar = dict(id=1, first_address=0, last_address=255,
                   next_auto_assign_mac=0)
        mac = dict(id=1, address=254)
        with self._stubs(ranges=(mar, 0), addresses=[Exception, mac]):
            address = self.ipam.allocate_mac_address(self.context, 0, 0, 0,
                                                     mac_address=254)
            self.assertEqual(address["address"], 254)


class QuarkNewMacAddressReallocationDeadlocks(QuarkIpamBaseTest):
    @contextlib.contextmanager
    def _stubs(self, addresses=None, ranges=None):
        if not addresses:
            addresses = [None]
        old_override = cfg.CONF.QUARK.mac_address_retry_max
        cfg.CONF.set_override('mac_address_retry_max', 1, 'QUARK')
        with contextlib.nested(
            mock.patch("quark.db.api.mac_address_find"),
            mock.patch("quark.db.api.mac_address_create"),
            mock.patch("quark.db.api."
                       "mac_address_range_find_allocation_counts"),
        ) as (mac_find, mac_create, mac_range_count):
            mac_find.side_effect = [Exception, None]
            mac_create.side_effect = addresses
            mac_range_count.return_value = ranges
            yield mac_find
        cfg.CONF.set_override('mac_address_retry_max', old_override, 'QUARK')

    def test_reallocate_mac_deadlock_raises_retry(self):
        mar = dict(id=1, first_address=0, last_address=255,
                   next_auto_assign_mac=0)
        mac = dict(id=1, address=254)
        with self._stubs(ranges=(mar, 0), addresses=[Exception, mac]) as (
                mac_find):
            with self.assertRaises(exceptions.MacAddressGenerationFailure):
                self.ipam.allocate_mac_address(self.context, 0, 0, 0)
            self.assertEqual(mac_find.call_count, 1)


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
    def test_deallocate_ips_by_port(self):
        port_dict = dict(ip_addresses=[], device_id="foo")
        addr_dict = dict(subnet_id=1, address_readable=None,
                         created_at=None, used_by_tenant_id=1)

        port = models.Port()
        port.update(port_dict)

        addr = models.IPAddress()
        addr.update(addr_dict)

        port["ip_addresses"].append(addr)
        self.ipam.deallocate_ips_by_port(self.context, port)
        # ORM takes care of other model if one model is modified
        self.assertTrue(len(addr["ports"]) == 0 or
                        len(port["ip_addresses"]) == 0)
        self.assertTrue(addr["deallocated"])

    def test_deallocate_ip_address_specific_ip(self):
        port_dict = dict(ip_addresses=[], device_id="foo")
        addr_dict = dict(subnet_id=1, address_readable="0.0.0.0",
                         created_at=None, used_by_tenant_id=1,
                         address=0)

        port = models.Port()
        port.update(port_dict)

        addr = models.IPAddress()
        addr.update(addr_dict)

        port["ip_addresses"].append(addr)
        to_delete = netaddr.IPAddress(addr["address"])
        self.ipam.deallocate_ips_by_port(self.context, port,
                                         ip_address=to_delete)
        # ORM takes care of other model if one model is modified
        self.assertTrue(len(addr["ports"]) == 0 or
                        len(port["ip_addresses"]) == 0)
        self.assertTrue(addr["deallocated"])

    def test_deallocate_ip_address_specific_ip_not_on_port_noop(self):
        port_dict = dict(ip_addresses=[], device_id="foo")
        addr_dict = dict(subnet_id=1, address_readable="0.0.0.0",
                         created_at=None, used_by_tenant_id=1,
                         address=0)

        port = models.Port()
        port.update(port_dict)

        addr = models.IPAddress()
        addr.update(addr_dict)

        port["ip_addresses"].append(addr)
        to_delete = netaddr.IPAddress(1)
        self.ipam.deallocate_ips_by_port(self.context, port,
                                         ip_address=to_delete)
        # ORM takes care of other model if one model is modified
        self.assertTrue(len(addr["ports"]) == 1 or
                        len(port["ip_addresses"]) == 1)
        self.assertFalse(addr["deallocated"])

    def test_deallocate_ip_address_multiple_ports_no_deallocation(self):
        port_dict = dict(ip_addresses=[])
        addr_dict = dict(deallocated=False)

        port = models.Port()
        port.update(port_dict)

        addr = models.IPAddress()
        addr.update(addr_dict)

        port["ip_addresses"].append(addr)
        addr["ports"].append(port)

        self.ipam.deallocate_ips_by_port(self.context, port)
        # ORM takes care of other model if one model is modified
        self.assertTrue(len(addr["ports"]) == 1 or
                        len(port["ip_addresses"]) == 0)
        self.assertFalse(addr["deallocated"])


class QuarkIpamTestBothIpAllocation(QuarkIpamBaseTest):
    def setUp(self):
        super(QuarkIpamTestBothIpAllocation, self).setUp()
        self.ipam = quark.ipam.QuarkIpamBOTH()
        self.v6_fip = netaddr.IPAddress("feed::")
        self.v6_lip = netaddr.IPAddress("feed::ff:ffff")
        self.v46_val = netaddr.IPAddress("::ffff:0.0.0.4").value

    @contextlib.contextmanager
    def _stubs(self, addresses=None, subnets=None):
        if not addresses:
            addresses = [None, None]
        with contextlib.nested(
            mock.patch("quark.db.api.ip_address_find"),
            mock.patch("quark.db.api.subnet_find_allocation_counts"),
            mock.patch("quark.db.api.subnet_find")
        ) as (addr_find, subnet_alloc_find, subnet_find):
            addr_find.side_effect = addresses
            if subnets and len(subnets[0]):
                subnet_find.return_value = [subnets[0][0][0]]
            subnet_alloc_find.side_effect = subnets
            yield

    def test_allocate_new_ip_address_two_empty_subnets(self):
        subnet4 = dict(id=1, first_ip=0, last_ip=255,
                       cidr="0.0.0.0/24", ip_version=4,
                       next_auto_assign_ip=1,
                       ip_policy=None)
        subnet6 = dict(id=1, first_ip=self.v6_fip.value,
                       last_ip=self.v6_lip.value, cidr="feed::/104",
                       ip_version=6, next_auto_assign_ip=self.v6_fip.value + 1,
                       ip_policy=None)
        with self._stubs(subnets=[[(subnet4, 0)], [(subnet6, 0)]],
                         addresses=[None, None, None, None]):
            address = []
            self.ipam.allocate_ip_address(self.context, address, 0, 0, 0)
            self.assertEqual(address[0]["address"],
                             netaddr.IPAddress('::ffff:0.0.0.1').value)
            self.assertEqual(address[0]["version"], 4)
            self.assertEqual(address[1]["address"], self.v6_fip.value + 1)
            self.assertEqual(address[1]["version"], 6)

    def test_allocate_new_ip_address_one_v4_subnet_open(self):
        subnet4 = dict(id=1, first_ip=0, last_ip=255,
                       cidr="0.0.0.0/24", ip_version=4,
                       next_auto_assign_ip=2,
                       ip_policy=None)
        with self._stubs(subnets=[[(subnet4, 0)], []],
                         addresses=[None, None, None, None]):
            address = []
            self.ipam.allocate_ip_address(self.context, address, 0, 0, 0)
            self.assertEqual(len(address), 1)
            self.assertEqual(address[0]["version"], 4)

    def test_allocate_new_ip_address_one_v6_subnet_open(self):
        subnet6 = dict(id=1, first_ip=self.v6_fip.value,
                       last_ip=self.v6_lip.value, cidr="feed::/104",
                       ip_version=6, next_auto_assign_ip=self.v6_fip.value + 1,
                       ip_policy=None)
        with self._stubs(subnets=[[], [(subnet6, 0)]],
                         addresses=[None, None, None, None]):
            address = []
            self.ipam.allocate_ip_address(self.context, address, 0, 0, 0)
            self.assertEqual(len(address), 1)
            self.assertEqual(address[0]["version"], 6)

    def test_allocate_provided_ip_address_one_v6_subnet_open(self):
        subnet6 = dict(id=1, first_ip=self.v6_fip.value,
                       last_ip=self.v6_lip.value, cidr="feed::/104",
                       ip_version=6, next_auto_assign_ip=self.v6_fip.value + 1,
                       ip_policy=None)
        with self._stubs(subnets=[[], [(subnet6, 0)]],
                         addresses=[None, None, None, None]):
            address = []
            ip_address = netaddr.IPAddress("feed::13")
            self.ipam.allocate_ip_address(self.context, address, 0, 0, 0,
                                          ip_address=ip_address)
            self.assertEqual(len(address), 1)
            self.assertEqual(ip_address,
                             netaddr.IPAddress(address[0]['address']))

    def test_allocate_new_ip_address_no_avail_subnets(self):
        with self._stubs(subnets=[[], []],
                         addresses=[None, None, None, None]):
            with self.assertRaises(exceptions.IpAddressGenerationFailure):
                addr = []
                self.ipam.allocate_ip_address(self.context, addr, 0, 0, 0)

    def test_reallocate_deallocated_v4_ip(self):
        network = netaddr.IPNetwork("feed::/104")
        fip = network.first
        lip = network.last
        subnet6 = dict(id=1, first_ip=fip, last_ip=lip,
                       cidr="feed::/104", ip_version=6,
                       next_auto_assign_ip=fip + 1,
                       ip_policy=None)
        network = netaddr.IPNetwork("0.0.0.0/24")
        first = network.ipv6().first
        last = network.ipv6().last
        target_ip = first + 4
        address = models.IPAddress()
        address["address"] = target_ip
        address["version"] = 4
        address["subnet"] = models.Subnet(cidr="0.0.0.0/24", first_ip=first,
                                          last_ip=last,
                                          next_auto_assign_ip=first)
        with self._stubs(subnets=[[(subnet6, 0)]],
                         addresses=[address, None, None]):
            address = []
            self.ipam.allocate_ip_address(self.context, address, 0, 0, 0)
            self.assertEqual(len(address), 2)
            self.assertEqual(address[0]["address"], target_ip)
            self.assertEqual(address[0]["version"], 4)
            self.assertEqual(address[1]["address"], fip + 1)
            self.assertEqual(address[1]["version"], 6)

    def test_reallocate_deallocated_v4_ip_passed_subnets(self):
        subnet4 = dict(id=1, first_ip=0, last_ip=255,
                       cidr="0.0.0.0/24", ip_version=4,
                       next_auto_assign_ip=0,
                       ip_policy=None)

        subnet6 = dict(id=1, first_ip=self.v6_fip.value,
                       last_ip=self.v6_lip.value, cidr="feed::/104",
                       ip_version=6, next_auto_assign_ip=self.v6_fip.value + 1,
                       ip_policy=None)
        address = models.IPAddress()

        address["address"] = self.v46_val
        address["version"] = 4
        address["subnet"] = models.Subnet(cidr="0.0.0.0/24")
        with self._stubs(subnets=[[(subnet6, 0)]],
                         addresses=[address, None, None]):
            address = []
            self.ipam.allocate_ip_address(self.context, address, 0, 0, 0,
                                          subnets=[subnet4])
            self.assertEqual(len(address), 2)
            self.assertEqual(address[0]["address"], self.v46_val)
            self.assertEqual(address[0]["version"], 4)
            self.assertEqual(address[1]["address"], self.v6_fip.value + 1)
            self.assertEqual(address[1]["version"], 6)

    def test_reallocate_deallocated_v4_ip_shared_net(self):
        subnet6 = dict(id=1, first_ip=self.v6_fip.value,
                       last_ip=self.v6_lip.value, cidr="feed::/104",
                       ip_version=6, next_auto_assign_ip=self.v6_fip.value + 1,
                       ip_policy=None)
        address = models.IPAddress()
        address["address"] = self.v46_val
        address["version"] = 4
        address["subnet"] = models.Subnet(cidr="0.0.0.0/24")
        with self._stubs(subnets=[[(subnet6, 0)]],
                         addresses=[address, None, None]):
            address = []
            self.ipam.allocate_ip_address(self.context, address, 0, 0, 0,
                                          segment_id="cell01")
            self.assertEqual(len(address), 2)
            self.assertEqual(address[0]["address"], self.v46_val)
            self.assertEqual(address[0]["version"], 4)
            self.assertEqual(address[1]["address"], self.v6_fip.value + 1)
            self.assertEqual(address[1]["version"], 6)

    def test_reallocate_deallocated_v4_ip_shared_net_no_subs_raises(self):
        with self._stubs(subnets=[], addresses=[None]):
            with self.assertRaises(exceptions.IpAddressGenerationFailure):
                addr = []
                self.ipam.allocate_ip_address(self.context, addr, 0, 0, 0,
                                              segment_id="cell01")

    def test_reallocate_deallocated_v4_ip_no_avail_subnets(self):
        address = models.IPAddress()
        address["address"] = self.v46_val
        address["version"] = 4
        address["subnet"] = models.Subnet(cidr="0.0.0.0/24")
        with self._stubs(subnets=[[]],
                         addresses=[address, None, None]):
            address = []
            self.ipam.allocate_ip_address(self.context, address, 0, 0, 0)
            self.assertEqual(len(address), 1)
            self.assertEqual(address[0]["address"], self.v46_val)
            self.assertEqual(address[0]["version"], 4)

    def test_reallocate_deallocated_v6_ip(self):
        subnet4 = dict(id=1, first_ip=0, last_ip=255,
                       cidr="0.0.0.0/24", ip_version=4,
                       next_auto_assign_ip=1,
                       ip_policy=None)
        address = models.IPAddress()
        address["address"] = netaddr.IPAddress(4).ipv6()
        address["version"] = 6
        address["subnet"] = models.Subnet(cidr="::ffff:0:0/96")
        with self._stubs(subnets=[[(subnet4, 0)]],
                         addresses=[address, None, None]):
            addresses = []
            self.ipam.allocate_ip_address(self.context, addresses, 0, 0, 0)
            self.assertEqual(len(addresses), 2)
            self.assertEqual(addresses[0]["address"], address["address"])
            self.assertEqual(addresses[0]["version"], 6)
            self.assertEqual(addresses[1]["address"],
                             netaddr.IPAddress('::ffff:0.0.0.1').value)
            self.assertEqual(addresses[1]["version"], 4)

    def test_reallocate_v6_with_mac_generates_rfc_address(self):
        subnet6 = dict(id=1, first_ip=self.v6_fip.value,
                       last_ip=self.v6_lip.value, cidr="feed::/104",
                       ip_version=6, next_auto_assign_ip=0,
                       ip_policy=None)

        address = models.IPAddress()
        address["address"] = self.v46_val
        address["version"] = 4
        address["subnet"] = models.Subnet(cidr="::ffff:0:0/96")

        mac = models.MacAddress()
        mac["address"] = netaddr.EUI("AA:BB:CC:DD:EE:FF")

        with self._stubs(subnets=[[(subnet6, 0)]],
                         addresses=[address, None, None]):
            address = []
            self.ipam.allocate_ip_address(self.context, address, 0, 0, 0,
                                          mac_address=mac)
            generated_v6 = netaddr.IPAddress("feed::a8bb:ccff:fedd:eeff")
            self.assertEqual(len(address), 2)
            self.assertEqual(address[0]["address"], self.v46_val)
            self.assertEqual(address[0]["version"], 4)
            self.assertEqual(address[1]["address"], generated_v6.value)
            self.assertEqual(address[1]["version"], 6)

    def test_reallocate_v6_with_mac_generates_exceeds_limit_raises(self):
        subnet6 = dict(cidr="feed::/104",
                       first_ip=self.v6_fip.value,
                       id=1,
                       ip_version=6,
                       ip_policy=None,
                       last_ip=self.v6_lip.value,
                       next_auto_assign_ip=0)

        address = models.IPAddress()
        address["address"] = self.v46_val
        address["version"] = 4
        address["subnet"] = models.Subnet(cidr="::ffff:0:0/96")

        mac = models.MacAddress()
        mac["address"] = netaddr.EUI("AA:BB:CC:DD:EE:FF")
        old_override = cfg.CONF.QUARK.v6_allocation_attempts

        cfg.CONF.set_override('v6_allocation_attempts', 0, 'QUARK')

        with self._stubs(subnets=[[(subnet6, 0)]],
                         addresses=[address, None, None]):
            with self.assertRaises(exceptions.IpAddressGenerationFailure):
                addr = []
                self.ipam.allocate_ip_address(self.context, addr, 0, 0, 0,
                                              mac_address=mac)
        cfg.CONF.set_override('v6_allocation_attempts', old_override, 'QUARK')

    def test_reallocate_deallocated_v6_ip_as_string_address(self):
        subnet4 = dict(id=1, first_ip=0, last_ip=255,
                       cidr="0.0.0.0/24", ip_version=4,
                       next_auto_assign_ip=1,
                       ip_policy=None)
        address = models.IPAddress()
        address["address"] = str(self.v46_val)
        address["version"] = 6
        address["subnet"] = models.Subnet(cidr="::ffff:0:0/96")
        with self._stubs(subnets=[[(subnet4, 0)]],
                         addresses=[address, None, None]):
            addresses = []
            self.ipam.allocate_ip_address(self.context, addresses, 0, 0, 0)
            self.assertEqual(len(addresses), 2)
            self.assertEqual(addresses[0]["address"], str(self.v46_val))
            self.assertEqual(addresses[0]["version"], 6)
            self.assertEqual(addresses[1]["address"],
                             netaddr.IPAddress("::ffff:0.0.0.1").value)
            self.assertEqual(addresses[1]["version"], 4)

    def test_reallocate_deallocated_v4_v6(self):
        address1 = models.IPAddress()
        address1["address"] = self.v46_val
        address1["version"] = 4
        address1["subnet"] = models.Subnet(cidr="0.0.0.0/24")
        address2 = models.IPAddress()
        address2["address"] = netaddr.IPAddress(42).ipv6()
        address2["version"] = 6
        address2["subnet"] = models.Subnet(cidr="::ffff:0:0/96")
        with self._stubs(subnets=[[]],
                         addresses=[address1, address2]):
            address = []
            self.ipam.allocate_ip_address(self.context, address, 0, 0, 0)
            self.assertEqual(len(address), 2)
            self.assertEqual(address[0]["address"], self.v46_val)
            self.assertEqual(address[0]["version"], 4)
            self.assertEqual(address[1]["address"], address2["address"])
            self.assertEqual(address[1]["version"], 6)


class QuarkIpamTestBothRequiredIpAllocation(QuarkIpamBaseTest):
    def setUp(self):
        super(QuarkIpamTestBothRequiredIpAllocation, self).setUp()
        self.ipam = quark.ipam.QuarkIpamBOTHREQ()
        self.v6_fip = netaddr.IPAddress("feed::")
        self.v6_lip = netaddr.IPAddress("feed::ff:ffff")
        self.v46_val = netaddr.IPAddress("::ffff:0.0.0.4").value

    @contextlib.contextmanager
    def _stubs(self, addresses=None, subnets=None):
        if not addresses:
            addresses = [None, None]
        self.context.session.add = mock.Mock()
        with contextlib.nested(
            mock.patch("quark.db.api.ip_address_find"),
            mock.patch("quark.db.api.subnet_find_allocation_counts")
        ) as (addr_find, subnet_find):
            addr_find.side_effect = addresses
            subnet_find.side_effect = subnets
            yield

    def test_allocate_new_ip_address_two_empty_subnets(self):
        subnet4 = dict(id=1, first_ip=0, last_ip=255,
                       cidr="0.0.0.0/24", ip_version=4,
                       next_auto_assign_ip=1,
                       ip_policy=None)
        subnet6 = dict(id=1, first_ip=self.v6_fip.value,
                       last_ip=self.v6_lip.value, cidr="feed::/104",
                       ip_version=6, next_auto_assign_ip=self.v6_fip.value + 1,
                       ip_policy=None)
        with self._stubs(subnets=[[(subnet4, 0)], [(subnet6, 0)]],
                         addresses=[None, None, None, None]):
            address = []
            self.ipam.allocate_ip_address(self.context, address, 0, 0, 0)
            self.assertEqual(address[0]["address"],
                             netaddr.IPAddress("::ffff:0.0.0.1").value)
            self.assertEqual(address[0]["version"], 4)
            self.assertEqual(address[1]["address"], self.v6_fip.value + 1)
            self.assertEqual(address[1]["version"], 6)

    def test_allocate_new_ip_address_one_v4_subnet_open(self):
        subnet4 = dict(id=1, first_ip=0, last_ip=255,
                       cidr="0.0.0.0/24", ip_version=4,
                       next_auto_assign_ip=2,
                       ip_policy=None)
        with self._stubs(subnets=[[(subnet4, 0)], []],
                         addresses=[None, None, None, None]):
            with self.assertRaises(exceptions.IpAddressGenerationFailure):
                self.ipam.allocate_ip_address(self.context, [], 0, 0, 0)

    def test_allocate_new_ip_address_one_v6_subnet_open(self):
        subnet6 = dict(id=1, first_ip=self.v6_fip, last_ip=self.v6_lip,
                       cidr="feed::/104", ip_version=6,
                       next_auto_assign_ip=2,
                       ip_policy=None)
        with self._stubs(subnets=[[], [(subnet6, 0)]],
                         addresses=[None, None, None, None]):
            with self.assertRaises(exceptions.IpAddressGenerationFailure):
                self.ipam.allocate_ip_address(self.context, [], 0, 0, 0)

    def test_allocate_new_ip_address_no_avail_subnets(self):
        with self._stubs(subnets=[[], []],
                         addresses=[None, None, None, None]):
            with self.assertRaises(exceptions.IpAddressGenerationFailure):
                addr = []
                self.ipam.allocate_ip_address(self.context, addr, 0, 0, 0)

    def test_reallocate_deallocated_v4_ip(self):
        subnet6 = dict(id=66, first_ip=self.v6_fip.value,
                       last_ip=self.v6_lip.value, cidr="feed::/104",
                       ip_version=6, next_auto_assign_ip=self.v6_fip.value + 1,
                       ip_policy=None)
        address = models.IPAddress()
        address["address"] = 4
        address["version"] = 4
        address["subnet"] = models.Subnet(cidr="0.0.0.0/24")
        with self._stubs(subnets=[[(subnet6, 0)]],
                         addresses=[address, None, None]):
            address = []
            self.ipam.allocate_ip_address(self.context, address, 0, 0, 0)
            self.assertEqual(len(address), 2)
            self.assertEqual(address[0]["address"], 4)
            self.assertEqual(address[0]["version"], 4)
            self.assertEqual(address[1]["address"], self.v6_fip.value + 1)
            self.assertEqual(address[1]["version"], 6)

    def test_reallocate_deallocated_v6_ip(self):
        subnet4 = dict(id=1, first_ip=0, last_ip=255, cidr="0.0.0.0/24",
                       ip_version=4, next_auto_assign_ip=1,
                       ip_policy=None)
        address = models.IPAddress()
        address["address"] = 4
        address["version"] = 6
        address["subnet"] = models.Subnet(cidr="::ffff:0:0/96")
        with self._stubs(subnets=[[(subnet4, 0)]],
                         addresses=[address, None, None]):
            addresses = []
            self.ipam.allocate_ip_address(self.context, addresses, 0, 0, 0)
            self.assertEqual(len(addresses), 2)
            self.assertEqual(addresses[0]["address"], address["address"])
            self.assertEqual(addresses[0]["version"], 6)
            self.assertEqual(addresses[1]["address"],
                             netaddr.IPAddress("::ffff:0.0.0.1").value)
            self.assertEqual(addresses[1]["version"], 4)

    def test_reallocate_deallocated_v4_v6(self):
        address1 = models.IPAddress()
        address1["address"] = self.v46_val
        address1["version"] = 4
        address1["subnet"] = models.Subnet(cidr="0.0.0.0/24")
        address2 = models.IPAddress()
        address2["address"] = 42
        address2["version"] = 6
        address2["subnet"] = models.Subnet(cidr="::ffff:0:0/96")
        with self._stubs(subnets=[[]],
                         addresses=[address1, address2]):
            address = []
            self.ipam.allocate_ip_address(self.context, address, 0, 0, 0)
            self.assertEqual(len(address), 2)
            self.assertEqual(address[0]["address"], self.v46_val)
            self.assertEqual(address[0]["version"], 4)
            self.assertEqual(address[1]["address"], address2["address"])
            self.assertEqual(address[1]["version"], 6)

    def test_allocate_allocate_ip_unsatisfied_strategy_fails(self):
        old_override = cfg.CONF.QUARK.ip_address_retry_max
        cfg.CONF.set_override('ip_address_retry_max', 1, 'QUARK')

        subnet4 = dict(id=1, first_ip=0, last_ip=255,
                       cidr="0.0.0.0/24", ip_version=4,
                       next_auto_assign_ip=1,
                       ip_policy=None)
        subnet6 = dict(id=1, first_ip=self.v6_fip.value,
                       last_ip=self.v6_lip.value, cidr="feed::/104",
                       ip_version=6, next_auto_assign_ip=-2,
                       ip_policy=dict(
                           size=2,
                           exclude=[
                               models.IPPolicyCIDR(cidr="feed::/128"),
                               models.IPPolicyCIDR(cidr="feed::ff:ffff/128")]))

        with self._stubs(subnets=[[(subnet4, 0)], [(subnet6, 0)]],
                         addresses=[None, None, None, None]):
            address = []
            with self.assertRaises(exceptions.IpAddressGenerationFailure):
                self.ipam.allocate_ip_address(self.context, address, 0, 0, 0)
            self.assertEqual(address[0]["address"],
                             netaddr.IPAddress("::ffff:0.0.0.1").value)

        cfg.CONF.set_override('ip_address_retry_max', old_override, 'QUARK')


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


class QuarkIpamAllocateFromV6Subnet(QuarkIpamBaseTest):
    @contextlib.contextmanager
    def _stubs(self, policies=None, ip_address=None, deallocated=True):
        self.context.session.add = mock.Mock()
        ip_mod = None
        if ip_address:
            ip_mod = models.IPAddress()
            ip_mod["address"] = ip_address.value
            ip_mod["deallocated"] = deallocated

        with contextlib.nested(
            mock.patch("quark.db.models.IPPolicy.get_ip_policy_cidrs"),
            mock.patch("quark.db.api.ip_address_find"),
            mock.patch("quark.db.api.ip_address_create"),
            mock.patch("quark.db.api.ip_address_update")
        ) as (policy_find, ip_address_find, ip_create, ip_update):
            policy_find.return_value = policies
            ip_address_find.return_value = ip_mod
            ip_create.return_value = ip_mod
            ip_update.return_value = ip_mod
            yield policy_find, ip_address_find, ip_create, ip_update

    def test_reallocate_v6_with_mac_fails_policy_raises(self):
        port_id = "945af340-ed34-4fec-8c87-853a2df492b4"
        subnet6 = dict(id=1, first_ip=0, last_ip=0,
                       cidr="feed::/104", ip_version=6,
                       next_auto_assign_ip=0,
                       ip_policy=None)

        mac = models.MacAddress()
        mac["address"] = netaddr.EUI("AA:BB:CC:DD:EE:FF")

        old_override = cfg.CONF.QUARK.v6_allocation_attempts
        cfg.CONF.set_override('v6_allocation_attempts', 1, 'QUARK')

        policy = netaddr.IPSet(["feed::/64"])
        with self._stubs(policies=policy):
            with self.assertRaises(exceptions.IpAddressGenerationFailure):
                self.ipam._allocate_from_v6_subnet(self.context, 0, subnet6,
                                                   port_id, self.reuse_after,
                                                   mac_address=mac)

        cfg.CONF.set_override('v6_allocation_attempts', old_override, 'QUARK')

    def test_reallocate_v6_with_mac(self):
        port_id = "945af340-ed34-4fec-8c87-853a2df492b4"
        subnet6 = dict(id=1, first_ip=0, last_ip=0,
                       cidr="feed::/104", ip_version=6,
                       next_auto_assign_ip=0,
                       ip_policy=None)

        mac = models.MacAddress()
        mac["address"] = netaddr.EUI("AA:BB:CC:DD:EE:FF")

        old_override = cfg.CONF.QUARK.v6_allocation_attempts
        cfg.CONF.set_override('v6_allocation_attempts', 1, 'QUARK')
        ip_address = netaddr.IPAddress("fe80::")

        with self._stubs(policies=[], ip_address=ip_address) as (
                policy_find, ip_find, ip_create, ip_update):
            a = self.ipam._allocate_from_v6_subnet(self.context, 0, subnet6,
                                                   port_id, self.reuse_after,
                                                   mac_address=mac)
            self.assertEqual(ip_address.value, a["address"])
            self.assertEqual(1, ip_update.call_count)
            self.assertEqual(0, ip_create.call_count)

        cfg.CONF.set_override('v6_allocation_attempts', old_override, 'QUARK')

    def test_allocate_v6_with_ip_and_no_mac(self):
        fip = netaddr.IPAddress('fe80::')
        ip_address = netaddr.IPAddress("fe80::7")
        lip = netaddr.IPAddress('fe80::FF:FFFF')
        port_id = "945af340-ed34-4fec-8c87-853a2df492b4"
        subnet6 = dict(id=1, first_ip=fip, last_ip=lip,
                       cidr="feed::/104", ip_version=6,
                       next_auto_assign_ip=fip, ip_policy=None)

        with self._stubs(policies=[], ip_address=ip_address) as (
                policy_find, ip_find, ip_create, ip_update):
            a = self.ipam._allocate_from_v6_subnet(self.context, 0, subnet6,
                                                   port_id, self.reuse_after,
                                                   ip_address=ip_address)
            self.assertEqual(a['address'], ip_address.value)


class QuarkIpamAllocateV6IPGeneration(QuarkIpamBaseTest):
    @contextlib.contextmanager
    def _stubs(self, ip_addresses, create_ip_return, update_ip_return):
        self.context.session.add = mock.Mock()
        ip_mods = []
        for ip in ip_addresses:
            ip_mod = models.IPAddress()
            ip_mod.update(ip)
            ip_mods.append(ip_mod)

        old_override = cfg.CONF.QUARK.v6_allocation_attempts
        cfg.CONF.set_override('v6_allocation_attempts', 2, 'QUARK')
        with contextlib.nested(
            mock.patch("quark.db.api.ip_address_find"),
            mock.patch("quark.db.api.ip_address_create"),
            mock.patch("quark.db.api.ip_address_update")
        ) as (ip_address_find, ip_create, ip_update):
            ip_address_find.side_effect = ip_mods
            ip_create.return_value = create_ip_return
            ip_update.return_value = update_ip_return
            yield ip_address_find, ip_create, ip_update
        cfg.CONF.set_override('v6_allocation_attempts', old_override, 'QUARK')

    def test_reallocate_v6_with_mac_already_exists(self):
        port_id = "945af340-ed34-4fec-8c87-853a2df492b4"
        subnet6 = dict(id=1, first_ip=0, last_ip=0,
                       cidr="feed::/104", ip_version=6,
                       next_auto_assign_ip=0,
                       ip_policy=None)

        ip1 = {"address": netaddr.IPAddress("fe80::").value,
               "deallocated": False}
        ip2 = {"address": netaddr.IPAddress("fe81::").value,
               "deallocated": True}

        mac = models.MacAddress()
        mac["address"] = netaddr.EUI("AA:BB:CC:DD:EE:FF")

        with self._stubs([ip1, ip2], ip2, ip2) as (
                ip_find, ip_create, ip_update):
            self.ipam._allocate_from_v6_subnet(self.context, 0, subnet6,
                                               port_id, self.reuse_after,
                                               mac_address=mac)
            self.assertEqual(1, ip_update.call_count)
            self.assertEqual(0, ip_create.call_count)


class QuarkNewIPAddressAllocation(QuarkIpamBaseTest):
    @contextlib.contextmanager
    def _stubs(self, addresses=None, subnets=None):
        if not addresses:
            addresses = [None]
        self.context.session.add = mock.Mock()
        with contextlib.nested(
            mock.patch("quark.db.api.ip_address_find"),
            mock.patch("quark.db.api.subnet_find_allocation_counts")
        ) as (addr_find, subnet_find):
            addr_find.side_effect = addresses
            subnet_find.return_value = subnets
            yield

    def test_allocate_new_ip_address_in_empty_range(self):
        subnet = dict(id=1, first_ip=0, last_ip=255,
                      cidr="0.0.0.0/24", ip_version=4,
                      next_auto_assign_ip=0,
                      ip_policy=dict(size=1, exclude=[
                          models.IPPolicyCIDR(cidr="0.0.0.0/32")]))
        with self._stubs(subnets=[(subnet, 0)], addresses=[None, None]):
            address = []
            self.ipam.allocate_ip_address(self.context, address, 0, 0, 0,
                                          version=4)
            self.assertEqual(address[0]["address"],
                             netaddr.IPAddress("::ffff:0.0.0.1").value)

    def test_allocate_ip_one_full_one_open_subnet(self):
        subnet1 = dict(id=1, first_ip=0, last_ip=0,
                       cidr="0.0.0.0/32", ip_version=4,
                       next_auto_assign_ip=0,
                       ip_policy=dict(size=1, exclude=[
                           models.IPPolicyCIDR(cidr="0.0.0.0/32")]))
        subnet2 = dict(id=2, first_ip=256, last_ip=512,
                       cidr="0.0.1.0/24", ip_version=4,
                       next_auto_assign_ip=256,
                       ip_policy=dict(
                           size=1,
                           exclude=[models.IPPolicyCIDR(cidr="0.0.1.0/32")]))
        subnets = [(subnet1, 1), (subnet2, 0)]
        with self._stubs(subnets=subnets, addresses=[None, None]):
            address = []
            self.ipam.allocate_ip_address(self.context, address, 0, 0, 0)
            self.assertEqual(address[0]["address"],
                             netaddr.IPAddress("::ffff:0.0.1.1").value)
            self.assertEqual(address[0]["subnet_id"], 2)

    def test_allocate_ip_no_subnet_fails(self):
        with self._stubs(subnets=[]):
            with self.assertRaises(exceptions.IpAddressGenerationFailure):
                self.ipam.allocate_ip_address(self.context, [], 0, 0, 0)

    def test_allocate_ip_no_available_subnet_fails(self):
        subnet1 = dict(id=1, first_ip=0, last_ip=0, next_auto_assign_ip=0,
                       cidr="0.0.0.0/32", ip_version=4,
                       ip_policy=dict(
                           size=1,
                           exclude=[models.IPPolicyCIDR(cidr="0.0.0.0/32")]))
        with self._stubs(subnets=[(subnet1, 1)]):
            with self.assertRaises(exceptions.IpAddressGenerationFailure):
                self.ipam.allocate_ip_address(self.context, [], 0, 0, 0)

    def test_allocate_ip_two_open_subnets_choses_first(self):
        subnet1 = dict(id=1, first_ip=0, last_ip=255,
                       cidr="0.0.0.0/24", ip_version=4,
                       next_auto_assign_ip=0,
                       ip_policy=dict(size=1, exclude=[
                           models.IPPolicyCIDR(cidr="0.0.0.0/32")]))
        subnet2 = dict(id=2, first_ip=256, last_ip=510,
                       cidr="0.0.1.0/24", ip_version=4,
                       next_auto_assign_ip=0,
                       ip_policy=dict(size=1, exclude=[
                           models.IPPolicyCIDR(cidr="0.0.1.0/32")]))
        subnets = [(subnet1, 1), (subnet2, 1)]
        with self._stubs(subnets=subnets, addresses=[None, None]):
            address = []
            self.ipam.allocate_ip_address(self.context, address, 0, 0, 0)
            self.assertEqual(address[0]["address"],
                             netaddr.IPAddress("::ffff:0.0.0.1").value)
            self.assertEqual(address[0]["subnet_id"], 1)

    def test_find_requested_ip_subnet(self):
        subnet1 = dict(id=1, first_ip=0, last_ip=255,
                       cidr="0.0.0.0/24", ip_version=4,
                       ip_policy=None)
        subnets = [(subnet1, 1)]
        with self._stubs(subnets=subnets, addresses=[None, None]):
            address = []
            self.ipam.allocate_ip_address(
                self.context, address, 0, 0, 0, ip_address="0.0.0.240")
            self.assertEqual(address[0]["address"],
                             netaddr.IPAddress('::ffff:0.0.0.240').value)
            self.assertEqual(address[0]["subnet_id"], 1)

    def test_no_valid_subnet_for_requested_ip_fails(self):
        subnet1 = dict(id=1, first_ip=0, last_ip=255,
                       cidr="0.0.1.0/24", ip_version=4)
        subnets = [(subnet1, 1)]
        with self._stubs(subnets=subnets, addresses=[None, None]):
            with self.assertRaises(exceptions.IpAddressGenerationFailure):
                self.ipam.allocate_ip_address(
                    self.context, [], 0, 0, 0, ip_address="0.0.0.240")


class QuarkIPAddressAllocationTestRetries(QuarkIpamBaseTest):
    @contextlib.contextmanager
    def _stubs(self, address=None, subnets=None):
        self.context.session.add = mock.Mock()
        with contextlib.nested(
            mock.patch("quark.db.api.ip_address_find"),
            mock.patch("quark.db.api.ip_address_create"),
            mock.patch("quark.ipam.QuarkIpam._notify_new_addresses"),
            mock.patch("quark.db.api.subnet_find_allocation_counts")
        ) as (addr_find, addr_create, notify, subnet_find):
            addr_find.side_effect = [None, None, None]
            addr_create.side_effect = address
            subnet_find.return_value = subnets
            yield

    def test_allocate_allocated_ip_fails_and_retries(self):
        subnet1 = dict(id=1, first_ip=0, last_ip=255, next_auto_assign_ip=1,
                       cidr="0.0.0.0/24", ip_version=4,
                       ip_policy=None)
        subnets = [(subnet1, 1)]
        addr_found = dict(id=1, address=2)
        with self._stubs(subnets=subnets,
                         address=[q_exc.IPAddressRetryableFailure,
                                  addr_found]):
            addr = []
            self.ipam.allocate_ip_address(self.context, addr, 0, 0, 0)
            self.assertEqual(subnet1["next_auto_assign_ip"], 3)
            self.assertEqual(addr[0]["address"], 2)

    def test_allocate_explicit_already_allocated_fails_and_retries(self):
        subnet1 = dict(id=1, first_ip=0, last_ip=255, next_auto_assign_ip=1,
                       cidr="0.0.0.0/24", ip_version=4,
                       ip_policy=None)
        subnets = [(subnet1, 1), (subnet1, 1)]
        addr_found = dict(id=1, address=1)
        with self._stubs(subnets=subnets,
                         address=[q_exc.IPAddressRetryableFailure,
                                  addr_found]):
            with self.assertRaises(exceptions.IpAddressInUse):
                self.ipam.allocate_ip_address(
                    self.context, [], 0, 0, 0, ip_address="0.0.0.1")

    def test_allocate_implicit_already_allocated_fails_and_retries(self):
        subnet1 = dict(id=1, first_ip=0, last_ip=255, next_auto_assign_ip=1,
                       cidr="::/64", ip_version=6,
                       ip_policy=None)
        subnets = [(subnet1, 1), (subnet1, 1)]
        addr_found = dict(id=1, address=1)

        with self._stubs(subnets=subnets,
                         address=[db_exc.DBDuplicateEntry, addr_found]):
            with mock.patch("quark.ipam.generate_v6") as gv6:
                gv6.return_value = (1, 2)
                ret_addrs = []
                self.ipam.allocate_ip_address(
                    self.context, ret_addrs, 0, 0, 0,
                    mac_address=dict(address=mock.MagicMock())),
                self.assertEqual(ret_addrs, [addr_found])

    def test_allocate_specific_subnet_ip_not_in_subnet_fails(self):
        subnet1 = dict(id=1, first_ip=0, last_ip=255, next_auto_assign_ip=1,
                       cidr="0.0.0.0/24", ip_version=4,
                       ip_policy=None)
        subnets = [(subnet1, 1), (subnet1, 1)]
        addr_found = dict(id=1, address=256)
        with self._stubs(subnets=subnets,
                         address=[q_exc.IPAddressRetryableFailure,
                                  addr_found]):
            with self.assertRaises(q_exc.IPAddressNotInSubnet):
                self.ipam.allocate_ip_address(
                    self.context, [], 0, 0, 0, ip_address="0.0.1.0",
                    subnets=subnet1)

    def test_allocate_specific_subnet_unusable_fails(self):
        subnet1 = dict(id=1, first_ip=0, last_ip=255, next_auto_assign_ip=1,
                       cidr="0.0.0.0/24", ip_version=4,
                       ip_policy=None,
                       do_not_use=1)
        subnets = []
        addr_found = dict(id=1, address=256)
        with self._stubs(subnets=subnets,
                         address=[q_exc.IPAddressRetryableFailure,
                                  addr_found]):
            with self.assertRaises(exceptions.IpAddressGenerationFailure):
                self.ipam.allocate_ip_address(
                    self.context, [], 0, 0, 0, ip_address="0.0.1.0",
                    subnets=subnet1)

    def test_allocate_last_ip_closes_subnet(self):
        subnet1 = dict(id=1, first_ip=0, last_ip=1, next_auto_assign_ip=1,
                       cidr="0.0.0.0/24", ip_version=4,
                       ip_policy=None)
        subnets = [(subnet1, 1)]
        addr_found = dict(id=1, address=1)
        with self._stubs(subnets=subnets, address=[addr_found]):
            addr = []
            self.ipam.allocate_ip_address(self.context, addr, 0, 0, 0)
            self.assertEqual(subnet1["next_auto_assign_ip"], -1)
            self.assertEqual(addr[0]["address"], 1)


class QuarkIPAddressAllocateDeallocated(QuarkIpamBaseTest):
    @contextlib.contextmanager
    def _stubs(self, ip_find, subnet, address, addresses_found,
               sub_found=True):
        with contextlib.nested(
            mock.patch("quark.db.api.ip_address_find"),
            mock.patch("quark.db.api.ip_address_update"),
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
                      cidr="0.0.0.0/24", ip_policy=None)
        address = dict(id=1, address=1, subnet=subnet)
        addresses_found = [None, address, None]
        with self._stubs(
            True, subnet, address, addresses_found
        ) as (choose_subnet):
            ipaddress = []
            self.ipam.allocate_ip_address(self.context, ipaddress, 0, 0, 0)
            self.assertIsNotNone(ipaddress[0]['id'])
            self.assertFalse(choose_subnet.called)

    def test_allocate_finds_deallocated_ip_out_of_range_deletes(self):
        subnet = dict(id=1, ip_version=4, next_auto_assign_ip=2,
                      cidr="0.0.0.0/29", ip_policy=None)
        address = dict(id=1, address=254)
        address2 = dict(id=1, address=1)
        address["subnet"] = subnet
        addresses_found = [address, address2]
        self.context.session.delete = mock.Mock()
        with self._stubs(False, subnet, address, addresses_found,
                         sub_found=True):
            addr = []
            self.ipam.allocate_ip_address(self.context, addr, 0, 0, 0)
            self.assertTrue(self.context.session.delete.called)
            self.assertEqual(len(addr), 1)
        self.context.session.delete = mock.Mock()

    def test_allocate_finds_no_deallocated_creates_new_ip(self):
        subnet = dict(id=1, ip_version=4, next_auto_assign_ip=2,
                      cidr="0.0.0.0/24", first_ip=0, last_ip=255,
                      ip_policy=None)
        address = dict(id=1, address=0)
        addresses_found = [None, address, None]
        with self._stubs(
            False, subnet, address, addresses_found
        ) as (choose_subnet):
            ipaddress = []
            self.ipam.allocate_ip_address(self.context, ipaddress, 0, 0, 0)
            self.assertIsNotNone(ipaddress[0]['id'])
            self.assertEqual(ipaddress[0]["address"],
                             netaddr.IPAddress("::ffff:0.0.0.1").value)
            self.assertTrue(choose_subnet.called)


class TestQuarkIpPoliciesIpAllocation(QuarkIpamBaseTest):
    @contextlib.contextmanager
    def _stubs(self, addresses=None, subnets=None):
        if not addresses:
            addresses = [None]
        self.context.session.add = mock.Mock()
        with contextlib.nested(
            mock.patch("quark.db.api.ip_address_find"),
            mock.patch("quark.db.api.subnet_find_allocation_counts")
        ) as (addr_find, subnet_find):
            addr_find.side_effect = addresses
            subnet_find.return_value = subnets
            yield

    def test_first_ip_is_not_network_ip_by_default(self):
        network = netaddr.IPNetwork("192.168.0.0/24")
        first = network.ipv6().first
        last = network.ipv6().last
        subnet = dict(id=1, first_ip=first, last_ip=last,
                      cidr="192.168.0.0/24", ip_version=4,
                      next_auto_assign_ip=first,
                      ip_policy=dict(size=1, exclude=[
                          models.IPPolicyCIDR(cidr="192.168.0.0/32")]))
        with self._stubs(subnets=[(subnet, 0)], addresses=[None, None]):
            address = []
            self.ipam.allocate_ip_address(self.context, address, 0, 0, 0,
                                          version=4)
            self.assertEqual(address[0]["address"], first + 1)

    def test_subnet_full_based_on_ip_policy(self):
        subnet = dict(id=1, first_ip=0, last_ip=255,
                      cidr="0.0.0.0/24", ip_version=4,
                      next_auto_assign_ip=0,
                      ip_policy=dict(size=256, exclude=[
                          models.IPPolicyCIDR(cidr="0.0.0.0/24")]))
        with self._stubs(subnets=[(subnet, 0)], addresses=[None, None]):
            with self.assertRaises(exceptions.IpAddressGenerationFailure):
                self.ipam.allocate_ip_address(self.context, [], 0, 0, 0,
                                              version=4)

    def test_ip_policy_on_subnet(self):
        old_override = cfg.CONF.QUARK.ip_address_retry_max
        cfg.CONF.set_override('ip_address_retry_max', 3, 'QUARK')
        subnet = dict(id=1, first_ip=0, last_ip=255,
                      cidr="0.0.0.0/24", ip_version=4,
                      next_auto_assign_ip=0,
                      ip_policy=dict(size=2, exclude=[
                          models.IPPolicyCIDR(cidr="0.0.0.0/31")]))
        with self._stubs(subnets=[(subnet, 0)], addresses=[None, None]):
            address = []
            self.ipam.allocate_ip_address(self.context, address, 0, 0, 0,
                                          version=4)
            self.assertEqual(address[0]["address"],
                             netaddr.IPAddress("::ffff:0.0.0.2").value)
        cfg.CONF.set_override('ip_address_retry_max', old_override, 'QUARK')

    def test_ip_policy_on_both_subnet_preferred(self):
        subnet = dict(id=1, first_ip=0, last_ip=255,
                      cidr="0.0.0.0/24", ip_version=4,
                      next_auto_assign_ip=0,
                      ip_policy=dict(size=1, exclude=[
                          models.IPPolicyCIDR(cidr="0.0.0.0/32")]))
        with self._stubs(subnets=[(subnet, 0)], addresses=[None, None]):
            address = []
            self.ipam.allocate_ip_address(self.context, address, 0, 0, 0,
                                          version=4)
            self.assertEqual(address[0]["address"],
                             netaddr.IPAddress("::ffff:0.0.0.1").value)

    def test_ip_policy_allows_specified_ip(self):
        subnet1 = dict(id=1, first_ip=0, last_ip=255,
                       cidr="0.0.0.0/24", ip_version=4,
                       ip_policy=dict(exclude=[
                           models.IPPolicyCIDR(cidr="0.0.0.240/32")]))
        subnets = [(subnet1, 1)]
        with self._stubs(subnets=subnets, addresses=[None, None]):
            address = []
            self.ipam.allocate_ip_address(
                self.context, address, 0, 0, 0, ip_address="0.0.0.240")
            self.assertEqual(address[0]["address"],
                             netaddr.IPAddress('::ffff:0.0.0.240').value)


class QuarkIPAddressAllocationNotifications(QuarkIpamBaseTest):
    @contextlib.contextmanager
    def _stubs(self, address, addresses=None, subnets=None, deleted_at=None):

        address = models.IPAddress(**address)
        if not addresses:
            addresses = [None]
        with contextlib.nested(
            mock.patch("quark.db.api.ip_address_find"),
            mock.patch("quark.db.api.ip_address_create"),
            mock.patch("quark.db.api.subnet_find_allocation_counts"),
            mock.patch("neutron.common.rpc.get_notifier"),
            mock.patch("neutron.openstack.common.timeutils.utcnow"),
        ) as (addr_find, addr_create, subnet_find, notify, time):
            addr_find.side_effect = addresses
            addr_create.return_value = address
            subnet_find.return_value = subnets
            time.return_value = deleted_at
            yield notify

    def test_allocation_notification(self):
        subnet = dict(id=1, first_ip=0, last_ip=255,
                      cidr="0.0.0.0/24", ip_version=4,
                      next_auto_assign_ip=0,
                      ip_policy=None)
        address = dict(address=0, created_at="123", subnet_id=1,
                       address_readable="0.0.0.0", used_by_tenant_id=1)
        with self._stubs(
            address,
            subnets=[(subnet, 1)],
            addresses=[None, None]
        ) as notify:
            addr = []
            self.ipam.allocate_ip_address(self.context, addr, 0, 0, 0,
                                          version=4)
            notify.assert_called_once_with("network")
            notify.return_value.info.assert_called_once_with(
                self.context,
                "ip_block.address.create",
                dict(ip_block_id=address["subnet_id"],
                     ip_address="0.0.0.0",
                     device_ids=[],
                     created_at=address["created_at"],
                     used_by_tenant_id=1))

    def test_deallocation_notification(self):
        addr_dict = dict(address=0, created_at="123", subnet_id=1,
                         address_readable="0.0.0.0", used_by_tenant_id=1)
        address = models.IPAddress()
        address.update(addr_dict)

        port_dict = dict(ip_addresses=[address], device_id="foo")
        port = models.Port()
        port.update(port_dict)
        address["ports"] = [port]

        with self._stubs(dict(), deleted_at="456") as notify:
            self.ipam.deallocate_ips_by_port(self.context, port)
            notify.assert_called_once_with("network")
            notify.return_value.info.assert_called_once_with(
                self.context,
                "ip_block.address.delete",
                dict(ip_block_id=address["subnet_id"],
                     ip_address="0.0.0.0",
                     device_ids=["foo"],
                     created_at=address["created_at"],
                     deleted_at="456",
                     used_by_tenant_id=1))


class QuarkIpamTestV6IpGeneration(QuarkIpamBaseTest):
    def test_rfc2462_generates_valid_ip(self):
        mac = netaddr.EUI("AA:BB:CC:DD:EE:FF")
        cidr = "fe80::/120"
        ip = quark.ipam.rfc2462_ip(mac, cidr)
        self.assertEqual(ip,
                         netaddr.IPAddress('fe80::a8bb:ccff:fedd:eeff').value)

    def test_rfc3041_generates_valid_ip(self):
        # Use a one-time generated UUID so the output is predictable
        port_id = "945af340-ed34-4fec-8c87-853a2df492b4"
        cidr = "fe80::/120"
        ip = quark.ipam.rfc3041_ip(port_id, cidr).next()
        self.assertEqual(ip,
                         netaddr.IPAddress('fe80::40c9:a95:d83a:2ffa').value)

    def test_v6_generator(self):
        mac = netaddr.EUI("AA:BB:CC:DD:EE:FF")
        cidr = "fe80::/120"
        port_id = "945af340-ed34-4fec-8c87-853a2df492b4"
        cidr = "fe80::/120"
        gen = quark.ipam.generate_v6(mac, port_id, cidr)
        ip = gen.next()
        self.assertEqual(ip,
                         netaddr.IPAddress('fe80::a8bb:ccff:fedd:eeff').value)
        ip = gen.next()
        self.assertEqual(ip,
                         netaddr.IPAddress('fe80::40c9:a95:d83a:2ffa').value)
