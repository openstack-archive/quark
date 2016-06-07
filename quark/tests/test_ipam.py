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
import json
import time

import mock
import netaddr
from neutron.common import exceptions as n_exc_ext
from neutron.common import rpc
from neutron_lib import exceptions as n_exc
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_utils import timeutils

from quark.db import models
from quark import exceptions as q_exc
import quark.ipam
from quark import network_strategy
from quark.tests import test_base


def subnet_helper(sub):
    if sub:
        if isinstance(sub, dict):
            policy = sub.pop("ip_policy", None)
            mod = models.Subnet(**sub)
            mod["next_auto_assign_ip"] = sub["next_auto_assign_ip"]
            mod["first_ip"] = sub["first_ip"]
            mod["last_ip"] = sub["last_ip"]
            if policy:
                mod["ip_policy"] = models.IPPolicy(**policy)
            return mod
        else:
            return sub
    return None


def ip_helper(ip):
    if ip:
        if isinstance(ip, dict):
            ip_mod = models.IPAddress(**ip)
            return ip_mod
        else:
            return ip
    return None


def mac_helper(mac):
    if mac:
        if isinstance(mac, dict):
            mac_mod = models.MacAddress(**mac)
            return mac_mod
        else:
            return mac
    return None


def range_helper(mac_range):
    if mac_range:
        if isinstance(mac_range, dict):
            mac_mod = models.MacAddressRange(**mac_range)
            return mac_mod
        else:
            return mac_range
    return None


class QuarkIpamBaseTest(test_base.TestBase):
    def setUp(self):
        super(QuarkIpamBaseTest, self).setUp()

        patcher = mock.patch("neutron.common.rpc.oslo_messaging")
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
    def _stubs(self, mac_find=True, do_not_use=False):
        address = dict(address=0)
        mac_range = dict(id=1, first_address=0, last_address=255,
                         next_auto_assign_mac=0, do_not_use=do_not_use,
                         cidr="AA:BB:CC/24")
        with contextlib.nested(
            mock.patch("quark.db.api.mac_address_reallocate"),
            mock.patch("quark.db.api.mac_address_reallocate_find"),
            mock.patch("quark.db.api."
                       "mac_address_range_find_allocation_counts"),
            mock.patch("quark.db.api.mac_address_create"),
            mock.patch("quark.db.api.mac_address_range_find"),
            mock.patch("quark.db.api.mac_address_delete"),
            mock.patch("quark.db.api.mac_range_update_next_auto_assign_mac"),
            mock.patch("quark.db.api.mac_range_update_set_full"),
            mock.patch("sqlalchemy.orm.session.Session.refresh")
        ) as (addr_realloc, addr_realloc_find, mac_range_count,
              mac_create, range_find, mac_delete, mac_auto_assign, set_full,
              refresh):
            address_mod = models.MacAddress(**address)
            range_mod = models.MacAddressRange(**mac_range)
            if mac_find:
                addr_realloc.return_value = True
                addr_realloc_find.return_value = address_mod
            else:
                addr_realloc.return_value = False
                addr_realloc_find.side_effect = [None, None]
            mac_range_count.return_value = (range_mod, 0)
            mac_create.return_value = address_mod
            range_find.return_value = range_mod

            def refresh_mock(mar):
                if mar["next_auto_assign_mac"] >= 0:
                    mar["next_auto_assign_mac"] += 1

            def set_full_mock(context, mar):
                mar["next_auto_assign_mac"] = -1
                return 1

            refresh.side_effect = refresh_mock
            set_full.side_effect = set_full_mock
            yield addr_realloc_find, mac_create, mac_delete, mac_auto_assign

    def test_allocate_mac_address_find_deallocated(self):
        with self._stubs(True) as (addr_realloc_find, mac_create, mac_delete,
                                   mac_auto_assign):
            self.ipam.allocate_mac_address(self.context, 0, 0, 0)
            self.assertTrue(addr_realloc_find.called)
            self.assertFalse(mac_create.called)
            self.assertFalse(mac_delete.called)
            self.assertFalse(mac_auto_assign.called)

    def test_allocate_mac_address_creates_new_mac(self):
        with self._stubs(False) as (addr_realloc_find, mac_create, mac_delete,
                                    mac_auto_assign):
            self.ipam.allocate_mac_address(self.context, 0, 0, 0)
            self.assertFalse(addr_realloc_find.called)
            self.assertTrue(mac_create.called)
            self.assertFalse(mac_delete.called)
            self.assertTrue(mac_auto_assign.called)


class QuarkNewMacAddressAllocation(QuarkIpamBaseTest):
    @contextlib.contextmanager
    def _stubs(self, addresses=None, ranges=None):
        if not addresses:
            addresses = [None]
        with contextlib.nested(
            mock.patch("quark.db.api.mac_address_find"),
            mock.patch("quark.db.api."
                       "mac_address_range_find_allocation_counts"),
            mock.patch("quark.db.api.mac_range_update_next_auto_assign_mac"),
            mock.patch("quark.db.api.mac_range_update_set_full"),
            mock.patch("sqlalchemy.orm.session.Session.refresh")
        ) as (mac_find, mac_range_count, mac_auto, mac_set_full, refresh):
            address_mod = [mac_helper(a) for a in addresses]
            range_mod = (range_helper(ranges[0]), ranges[1])
            mac_find.side_effect = address_mod
            mac_range_count.return_value = range_mod

            def refresh_mock(mar):
                if mar["next_auto_assign_mac"] >= 0:
                    mar["next_auto_assign_mac"] += 1

            def set_full_mock(context, mar):
                mar["next_auto_assign_mac"] = -1
                return 1

            refresh.side_effect = refresh_mock
            mac_set_full.side_effect = set_full_mock
            refresh.side_effect = refresh_mock

            yield range_mod

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
        with self._stubs(ranges=(None, 0)):
            with self.assertRaises(n_exc_ext.MacAddressGenerationFailure):
                self.ipam.allocate_mac_address(self.context, 0, 0, 0)

    def test_allocate_mac_no_available_range_fails(self):
        ranges = (None, 0)
        with self._stubs(ranges=ranges):
            with self.assertRaises(n_exc_ext.MacAddressGenerationFailure):
                self.ipam.allocate_mac_address(self.context, 0, 0, 0)

    def test_allocate_mac_next_to_last_in_range(self):
        mar = dict(id=1, first_address=0, last_address=2,
                   next_auto_assign_mac=1)
        with self._stubs(ranges=(mar, 0), addresses=[None, None]) as mr:
            address = self.ipam.allocate_mac_address(self.context, 0, 0, 0)
            self.assertEqual(address["address"], 1)
            self.assertEqual(mr[0]["next_auto_assign_mac"], 2)

    def test_allocate_mac_last_mac_in_range_closes_range(self):
        mar = dict(id=1, first_address=0, last_address=0,
                   next_auto_assign_mac=1)
        with self._stubs(ranges=(mar, 0), addresses=[None, None]) as mr:
            address = self.ipam.allocate_mac_address(self.context, 0, 0, 0)
            self.assertEqual(address["address"], 1)
            self.assertEqual(mr[0]["next_auto_assign_mac"], -1)

    def test_allocate_mac_range_unexpectedly_filled_closes(self):
        mar = dict(id=1, first_address=0, last_address=1,
                   next_auto_assign_mac=1)
        with self._stubs(ranges=(mar, 4), addresses=[None, None]) as mr:
            with self.assertRaises(n_exc_ext.MacAddressGenerationFailure):
                self.ipam.allocate_mac_address(self.context, 0, 0, 0)
            self.assertEqual(mr[0]["next_auto_assign_mac"], -1)


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
            address_mod = [mac_helper(a) for a in addresses]
            mac_create.side_effect = address_mod
            mac_range_count.return_value = ranges
            range_mod = (range_helper(ranges[0]), ranges[1])
            mac_range_count.return_value = range_mod
            yield

    def test_allocate_existing_mac_fails_and_retries(self):
        mar = dict(id=1, first_address=0, last_address=255,
                   next_auto_assign_mac=0)
        mac = dict(address=254)
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
            mock.patch("quark.db.api.mac_address_reallocate"),
            mock.patch("quark.db.api.mac_address_create"),
            mock.patch("quark.db.api."
                       "mac_address_range_find_allocation_counts"),
        ) as (mac_realloc, mac_create, mac_range_count):
            mac_realloc.side_effect = [Exception, None]
            mac_create.side_effect = addresses
            mac_range_count.return_value = ranges
            yield mac_realloc
        cfg.CONF.set_override('mac_address_retry_max', old_override, 'QUARK')

    def test_reallocate_mac_exception_raises_retry(self):
        mar = dict(id=1, first_address=0, last_address=255,
                   next_auto_assign_mac=0)
        mac = dict(id=1, address=254)
        with self._stubs(ranges=(mar, 0), addresses=[Exception, mac]) as (
                mac_realloc):
            with self.assertRaises(n_exc_ext.MacAddressGenerationFailure):
                self.ipam.allocate_mac_address(self.context, 0, 0, 0)
            self.assertEqual(mac_realloc.call_count, 1)


class QuarkMacAddressDeallocation(QuarkIpamBaseTest):
    @contextlib.contextmanager
    def _stubs(self, mac, mac_range):
        with contextlib.nested(
            mock.patch("quark.db.api.mac_address_find"),
            mock.patch("quark.db.api.mac_address_update"),
            mock.patch("quark.db.api.mac_address_range_find"),
            mock.patch("quark.db.api.mac_address_delete")
        ) as (mac_find, mac_update, range_find, mac_delete):
            mac_update.return_value = mac
            mac_find.return_value = mac
            range_find.return_value = mac_range
            yield mac_update, mac_delete

    def test_deallocate_mac(self):
        mac_range = dict(id=2, do_not_use=False)
        mac = dict(id=1, address=1, mac_address_range_id=mac_range["id"],
                   mac_address_range=mac_range)
        with self._stubs(mac=mac, mac_range=mac_range) as (mac_update,
                                                           mac_delete):
            self.ipam.deallocate_mac_address(self.context, mac["address"])
            self.assertTrue(mac_update.called)

    def test_deallocate_mac_do_not_use_range_deletes_mac(self):
        mac_range = dict(id=2, do_not_use=True)
        mac = dict(id=1, address=1, mac_address_range_id=mac_range["id"],
                   mac_address_range=mac_range)
        with self._stubs(mac=mac, mac_range=mac_range) as (mac_update,
                                                           mac_delete):
            self.ipam.deallocate_mac_address(self.context, mac["address"])
            self.assertFalse(mac_update.called)
            self.assertTrue(mac_delete.called)

    def test_deallocate_mac_mac_not_found_fails(self):
        with self._stubs(mac=None, mac_range=None) as (mac_update, mac_delete):
            self.assertRaises(n_exc.NotFound,
                              self.ipam.deallocate_mac_address, self.context,
                              0)
            self.assertFalse(mac_update.called)


class QuarkIPAddressDeallocation(QuarkIpamBaseTest):
    def test_deallocate_ips_by_port(self):
        port_dict = dict(ip_addresses=[], device_id="foo")
        addr_dict = dict(subnet_id=1, address_readable=None,
                         created_at=None, used_by_tenant_id=1,
                         version=4)

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
        self.assertEqual(addr["address_type"], None)

    def test_deallocate_ip_address_specific_ip(self):
        port_dict = dict(ip_addresses=[], device_id="foo")
        addr_dict = dict(subnet_id=1, address_readable="0.0.0.0",
                         created_at=None, used_by_tenant_id=1,
                         address=0, version=4)

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
        self.assertEqual(addr["address_type"], None)

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
        self.assertEqual(addr["address_type"], None)

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
        self.assertEqual(addr["address_type"], None)

    @mock.patch("quark.db.api.ip_address_delete")
    def test_deallocate_v6_ips_by_port(self, ip_delete):
        ip = netaddr.IPAddress("fe80::1")
        port_dict = dict(ip_addresses=[], device_id="foo")
        addr_dict = dict(subnet_id=1, address_readable=ip.value,
                         created_at=None, used_by_tenant_id=1,
                         version=6)

        port = models.Port()
        port.update(port_dict)

        addr = models.IPAddress()
        addr.update(addr_dict)

        port["ip_addresses"].append(addr)
        self.ipam.deallocate_ips_by_port(self.context, port)
        self.assertTrue(len(addr["ports"]) == 0 or
                        len(port["ip_addresses"]) == 0)
        ip_delete.assert_called_once_with(self.context, addr)
        self.assertEqual(addr["address_type"], None)


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
            mock.patch("quark.db.api.ip_address_reallocate"),
            mock.patch("quark.db.api.ip_address_reallocate_find"),
            mock.patch("quark.db.api.ip_address_find"),
            mock.patch("quark.db.api.subnet_find_ordered_by_most_full"),
            mock.patch("quark.db.api.subnet_find"),
            mock.patch("quark.db.api.subnet_update_next_auto_assign_ip"),
            mock.patch("quark.db.api.subnet_update_set_full"),
            mock.patch("sqlalchemy.orm.session.Session.refresh")
        ) as (addr_realloc, addr_realloc_find, addr_find,
              subnet_alloc_find, subnet_find, subnet_update,
              subnet_set_full, refresh):
            addr_mods = []
            sub_mods = []
            for a in addresses:
                addr_mods.append(ip_helper(a))

            for sub_list in subnets:
                sub_mod_list = []
                if not sub_list:
                    sub_mods.append([])
                    continue

                for sub in sub_list:
                    if sub[0]:
                        sub_mod_list.append((subnet_helper(sub[0]), sub[1]))
                    else:
                        sub_mod_list.append(sub)
                sub_mods.append(sub_mod_list)

            addr_realloc.side_effect = addr_mods[:1]
            addr_realloc_find.side_effect = addr_mods[:1]
            addr_find.side_effect = addr_mods[1:]
            if sub_mods and len(sub_mods[0]):
                subnet_find.return_value = [sub_mods[0][0][0]]
            subnet_alloc_find.side_effect = sub_mods
            subnet_update.return_value = 1

            def refresh_mock(sub):
                if sub["next_auto_assign_ip"] >= 0:
                    sub["next_auto_assign_ip"] += 1

            def set_full_mock(context, sub):
                sub["next_auto_assign_ip"] = -1
                return 1

            refresh.side_effect = refresh_mock
            subnet_set_full.side_effect = set_full_mock

            yield addr_realloc

    def test_allocate_subnets_at_max_will_not_allocate(self):
        # NOTE(mdietz): NCP-1480 - the test impl didn't match the
        #               intent, and shouldn't have actually passed
        #               as it was described.
        net1 = netaddr.IPNetwork("0.0.0.0/24")
        subnet4_1 = dict(id=1, first_ip=net1.first, last_ip=net1.last,
                         cidr=net1.cidr, ip_version=net1.version,
                         next_auto_assign_ip=255,
                         ip_policy=dict(size=2))
        net2 = netaddr.IPNetwork("1.1.1.0/24")
        subnet4_2 = dict(id=2, first_ip=net2.first, last_ip=net2.last,
                         cidr=net2.cidr, ip_version=net2.version,
                         next_auto_assign_ip=16843263,
                         ip_policy=dict(size=2))
        net3 = netaddr.IPNetwork("2.2.2.0/24")
        subnet4_3 = dict(id=3, first_ip=net3.first, last_ip=net3.last,
                         cidr=net3.cidr, ip_version=net3.version,
                         next_auto_assign_ip=33686271,
                         ip_policy=dict(size=2))
        subnet6 = dict(id=1, first_ip=self.v6_fip.value,
                       last_ip=self.v6_lip.value, cidr="feed::/104",
                       ip_version=6, next_auto_assign_ip=self.v6_lip.value,
                       ip_policy=dict(size=2))
        with self._stubs(subnets=[[(subnet4_1, 255), (subnet4_2, 255),
                                   (subnet4_3, 255)],
                                  [(subnet6, self.v6_lip.value - 1)]],
                         addresses=[None, None, None, None]):
            with self.assertRaises(n_exc.IpAddressGenerationFailure):
                self.ipam.allocate_ip_address(self.context, [], 0, 0, 0)

    def test_allocate_new_ip_address_two_empty_subnets(self):
        mac_address = 0
        expected_v6 = netaddr.IPAddress('feed::200:ff:fe00:0')
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
            self.ipam.allocate_ip_address(self.context, address, 0, 0, 0,
                                          mac_address=mac_address)
            self.assertEqual(address[0]["address"],
                             netaddr.IPAddress('::ffff:0.0.0.1').value)
            self.assertEqual(address[0]["version"], 4)
            self.assertEqual(address[0]['address_type'], 'fixed')
            self.assertEqual(address[1]["address"], expected_v6.value)
            self.assertEqual(address[1]["version"], 6)
            self.assertEqual(address[1]['address_type'], 'fixed')

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
        mac_address = 0
        subnet6 = dict(id=1, first_ip=self.v6_fip.value,
                       last_ip=self.v6_lip.value, cidr="feed::/104",
                       ip_version=6, next_auto_assign_ip=self.v6_fip.value + 1,
                       ip_policy=None)
        with self._stubs(subnets=[[], [(subnet6, 0)]],
                         addresses=[None, None, None, None]):
            address = []
            self.ipam.allocate_ip_address(self.context, address, 0, 0, 0,
                                          mac_address=mac_address)
            self.assertEqual(len(address), 1)
            self.assertEqual(address[0]["version"], 6)
            self.assertEqual(address[0]['address_type'], 'fixed')

    def test_allocate_fixed_ip_address_one_v6_subnet_open(self):
        mac_address = 0
        subnet6 = dict(id=1, first_ip=self.v6_fip.value,
                       last_ip=self.v6_lip.value, cidr="feed::/104",
                       ip_version=6, next_auto_assign_ip=self.v6_fip.value + 1,
                       ip_policy=None)
        with self._stubs(subnets=[[], [(subnet6, 0)]],
                         addresses=[None, None, None, None]):
            address = []
            ip_address = netaddr.IPAddress("feed::13")
            self.ipam.allocate_ip_address(self.context, address, 0, 0, 0,
                                          ip_addresses=[ip_address],
                                          mac_address=mac_address)
            self.assertEqual(len(address), 1)
            self.assertEqual(address[0]['address_type'], 'fixed')
            self.assertEqual(ip_address,
                             netaddr.IPAddress(address[0]['address']))

    def test_allocate_new_ip_address_no_avail_subnets(self):
        with self._stubs(subnets=[[], []],
                         addresses=[None, None, None, None]):
            with self.assertRaises(n_exc.IpAddressGenerationFailure):
                addr = []
                self.ipam.allocate_ip_address(self.context, addr, 0, 0, 0)

    def test_reallocate_deallocated_v4_ip(self):
        mac_address = 0
        expected_v6 = netaddr.IPAddress('feed::200:ff:fe00:0')
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
        address["allocated_at"] = timeutils.utcnow()
        with self._stubs(subnets=[[(subnet6, 0)]],
                         addresses=[address, None, None]) as addr_realloc:
            address = []
            self.ipam.allocate_ip_address(self.context, address, 0, 0, 0,
                                          mac_address=mac_address)
            self.assertEqual(len(address), 2)
            self.assertEqual(address[0]["address"], target_ip)
            self.assertEqual(address[0]["version"], 4)
            self.assertEqual(
                addr_realloc.call_args[0][1][models.IPAddress.address_type],
                "fixed")
            self.assertEqual(address[1]["address"], expected_v6.value)
            self.assertEqual(address[1]["version"], 6)
            self.assertEqual(address[1]['address_type'], 'fixed')

    def test_reallocate_deallocated_v4_ip_passed_subnets(self):
        mac_address = 0
        expected_v6 = netaddr.IPAddress('feed::200:ff:fe00:0')
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
        address["allocated_at"] = timeutils.utcnow()
        with self._stubs(subnets=[[(subnet6, 0)]],
                         addresses=[address, None, None]) as addr_realloc:
            address = []
            self.ipam.allocate_ip_address(self.context, address, 0, 0, 0,
                                          subnets=[subnet4['id']],
                                          mac_address=mac_address)
            self.assertEqual(len(address), 2)
            self.assertEqual(address[0]["address"], self.v46_val)
            self.assertEqual(address[0]["version"], 4)
            self.assertEqual(
                addr_realloc.call_args[0][1][models.IPAddress.address_type],
                "fixed")
            self.assertEqual(address[1]["address"], expected_v6.value)
            self.assertEqual(address[1]["version"], 6)
            self.assertEqual(address[1]['address_type'], 'fixed')

    def test_reallocate_deallocated_v4_ip_shared_net(self):
        mac_address = 0
        expected_v6 = netaddr.IPAddress('feed::200:ff:fe00:0')
        subnet6 = dict(id=1, first_ip=self.v6_fip.value,
                       last_ip=self.v6_lip.value, cidr="feed::/104",
                       ip_version=6, next_auto_assign_ip=self.v6_fip.value + 1,
                       ip_policy=None)
        address = models.IPAddress()
        address["address"] = self.v46_val
        address["version"] = 4
        address["subnet"] = models.Subnet(cidr="0.0.0.0/24")
        address["allocated_at"] = timeutils.utcnow()
        with self._stubs(subnets=[[(subnet6, 0)]],
                         addresses=[address, None, None]) as addr_realloc:
            address = []
            self.ipam.allocate_ip_address(self.context, address, 0, 0, 0,
                                          segment_id="cell01",
                                          mac_address=mac_address)
            self.assertEqual(len(address), 2)
            self.assertEqual(address[0]["address"], self.v46_val)
            self.assertEqual(address[0]["version"], 4)
            self.assertEqual(
                addr_realloc.call_args[0][1][models.IPAddress.address_type],
                "fixed")
            self.assertEqual(address[1]["address"], expected_v6.value)
            self.assertEqual(address[1]["version"], 6)
            self.assertEqual(address[1]['address_type'], 'fixed')

    def test_reallocate_deallocated_v4_ip_shared_net_no_subs_raises(self):
        with self._stubs(subnets=[], addresses=[None]):
            with self.assertRaises(n_exc.IpAddressGenerationFailure):
                addr = []
                self.ipam.allocate_ip_address(self.context, addr, 0, 0, 0,
                                              segment_id="cell01")

    def test_reallocate_deallocated_v4_ip_no_avail_subnets(self):
        address = models.IPAddress()
        address["address"] = self.v46_val
        address["version"] = 4
        address["subnet"] = models.Subnet(cidr="0.0.0.0/24")
        address["allocated_at"] = timeutils.utcnow()
        with self._stubs(subnets=[[]],
                         addresses=[address, None, None]) as addr_realloc:
            address = []
            self.ipam.allocate_ip_address(self.context, address, 0, 0, 0)
            self.assertEqual(len(address), 1)
            self.assertEqual(address[0]["address"], self.v46_val)
            self.assertEqual(address[0]["version"], 4)
            self.assertEqual(
                addr_realloc.call_args[0][1][models.IPAddress.address_type],
                "fixed")

    def test_allocate_v6_with_mac_generates_rfc_address(self):
        subnet6 = dict(id=1, first_ip=self.v6_fip.value,
                       last_ip=self.v6_lip.value, cidr="feed::/104",
                       ip_version=6, next_auto_assign_ip=self.v6_fip.value,
                       ip_policy=None)

        address = models.IPAddress()
        address["address"] = self.v46_val
        address["version"] = 4
        address["subnet"] = models.Subnet(cidr="::ffff:0:0/96")
        address["allocated_at"] = timeutils.utcnow()

        mac = models.MacAddress()
        mac["address"] = netaddr.EUI("AA:BB:CC:DD:EE:FF")

        with self._stubs(subnets=[[(subnet6, 0)]],
                         addresses=[address, None, None]) as addr_realloc:
            address = []
            self.ipam.allocate_ip_address(self.context, address, 0, 0, 0,
                                          mac_address=mac)
            generated_v6 = netaddr.IPAddress("feed::a8bb:ccff:fedd:eeff")
            self.assertEqual(len(address), 2)
            self.assertEqual(address[0]["address"], self.v46_val)
            self.assertEqual(address[0]["version"], 4)
            self.assertEqual(
                addr_realloc.call_args[0][1][models.IPAddress.address_type],
                "fixed")

            self.assertEqual(address[1]["address"], generated_v6.value)
            self.assertEqual(address[1]["version"], 6)
            self.assertEqual(address[1]['address_type'], 'fixed')

    def test_allocate_v6_with_mac_generates_exceeds_limit_raises(self):
        subnet6 = dict(cidr="feed::/104",
                       first_ip=self.v6_fip.value,
                       id=1,
                       ip_version=6,
                       ip_policy=None,
                       last_ip=self.v6_lip.value,
                       next_auto_assign_ip=self.v6_fip.value)

        address = models.IPAddress()
        address["address"] = self.v46_val
        address["version"] = 4
        address["subnet"] = models.Subnet(cidr="::ffff:0:0/96")
        address["allocated_at"] = timeutils.utcnow()

        mac = models.MacAddress()
        mac["address"] = netaddr.EUI("AA:BB:CC:DD:EE:FF")
        old_override = cfg.CONF.QUARK.v6_allocation_attempts

        cfg.CONF.set_override('v6_allocation_attempts', 0, 'QUARK')

        with self._stubs(subnets=[[(subnet6, 0)]],
                         addresses=[address, None, None]):
            with self.assertRaises(n_exc.IpAddressGenerationFailure):
                addr = []
                self.ipam.allocate_ip_address(self.context, addr, 0, 0, 0,
                                              mac_address=mac)
        cfg.CONF.set_override('v6_allocation_attempts', old_override, 'QUARK')

    def test_allocate_deallocated_v6_ip_as_string_address(self):
        subnet4 = dict(id=1, first_ip=0, last_ip=255,
                       cidr="0.0.0.0/24", ip_version=4,
                       next_auto_assign_ip=1,
                       ip_policy=None)
        address = models.IPAddress()
        address["address"] = str(self.v46_val)
        address["version"] = 6
        address["subnet"] = models.Subnet(cidr="::ffff:0:0/96")
        address["allocated_at"] = timeutils.utcnow()
        with self._stubs(subnets=[[(subnet4, 0)]],
                         addresses=[address, None, None]) as addr_realloc:
            addresses = []
            self.ipam.allocate_ip_address(self.context, addresses, 0, 0, 0)
            self.assertEqual(len(addresses), 2)
            self.assertEqual(addresses[0]["address"], str(self.v46_val))
            self.assertEqual(addresses[0]["version"], 6)
            self.assertEqual(
                addr_realloc.call_args[0][1][models.IPAddress.address_type],
                "fixed")

            self.assertEqual(addresses[1]["address"],
                             netaddr.IPAddress("::ffff:0.0.0.1").value)
            self.assertEqual(addresses[1]["version"], 4)
            self.assertEqual(addresses[1]['address_type'], 'fixed')

    def test_reallocate_deallocated_v4_with_v6(self):
        subnet6 = dict(cidr="feed::/104", first_ip=self.v6_fip.value,
                       id=1, ip_version=6, ip_policy=None,
                       last_ip=self.v6_lip.value,
                       next_auto_assign_ip=self.v6_fip.value)
        mac_address = 0
        address1 = models.IPAddress()
        address1["address"] = self.v46_val
        address1["version"] = 4
        address1["subnet"] = models.Subnet(cidr="0.0.0.0/24")
        address1["allocated_at"] = timeutils.utcnow()

        with self._stubs(subnets=[[(subnet6, 1)]],
                         addresses=[address1]) as addr_realloc:
            address = []
            self.ipam.allocate_ip_address(self.context, address, 0, 0, 0,
                                          mac_address=mac_address)
            self.assertEqual(len(address), 2)
            self.assertEqual(address[0]["address"], self.v46_val)
            self.assertEqual(address[0]["version"], 4)
            self.assertEqual(
                addr_realloc.call_args[0][1][models.IPAddress.address_type],
                "fixed")

            expected_v6 = netaddr.IPAddress("feed::200:ff:fe00:0")
            self.assertEqual(address[1]["address"], expected_v6.value)
            self.assertEqual(address[1]["version"], 6)
            self.assertEqual(address[1]['address_type'], 'fixed')


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
            mock.patch("quark.db.api.ip_address_reallocate"),
            mock.patch("quark.db.api.ip_address_reallocate_find"),
            mock.patch("quark.db.api.ip_address_find"),
            mock.patch("quark.db.api.subnet_find_ordered_by_most_full"),
            mock.patch("quark.db.api.subnet_update_next_auto_assign_ip"),
            mock.patch("quark.db.api.subnet_update_set_full"),
            mock.patch("sqlalchemy.orm.session.Session.refresh")
        ) as (addr_realloc, addr_realloc_find, addr_find,
              subnet_find, subnet_update, subnet_set_full, refresh):
            addrs = [ip_helper(a) for a in addresses]
            addr_realloc.side_effect = addrs[:1]
            addr_realloc_find.side_effect = addrs[:1]
            addr_find.side_effect = addrs[1:]

            sub_mods = []
            for sub_list in subnets:
                sub_mod_list = []
                if not sub_list:
                    sub_mods.append([])
                    continue
                for sub in sub_list:
                    if sub[0]:
                        sub_mod_list.append((subnet_helper(sub[0]), sub[1]))
                    else:
                        sub_mod_list.append(sub)

                sub_mods.append(sub_mod_list)
            subnet_find.side_effect = sub_mods
            subnet_update.return_value = 1

            def refresh_mock(sub):
                if sub["next_auto_assign_ip"] != -1:
                    sub["next_auto_assign_ip"] += 1

            def set_full_mock(context, sub):
                sub["next_auto_assign_ip"] = -1
                return 1

            refresh.side_effect = refresh_mock
            subnet_set_full.side_effect = set_full_mock

            yield addr_realloc

    def test_allocate_new_ip_address_two_empty_subnets(self):
        mac_address = 0
        expected_v6 = netaddr.IPAddress('feed::200:ff:fe00:0')
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
            self.ipam.allocate_ip_address(self.context, address, 0, 0, 0,
                                          mac_address=mac_address)
            self.assertEqual(address[0]["address"],
                             netaddr.IPAddress("::ffff:0.0.0.1").value)
            self.assertEqual(address[0]["version"], 4)
            self.assertEqual(address[0]['address_type'], 'fixed')
            self.assertEqual(address[1]["address"], expected_v6.value)
            self.assertEqual(address[1]["version"], 6)
            self.assertEqual(address[1]['address_type'], 'fixed')

    def test_allocate_new_ip_address_one_v4_subnet_open(self):
        subnet4 = dict(id=1, first_ip=0, last_ip=255,
                       cidr="0.0.0.0/24", ip_version=4,
                       next_auto_assign_ip=2,
                       ip_policy=None)
        with self._stubs(subnets=[[(subnet4, 0)], []],
                         addresses=[None, None, None, None]):
            with self.assertRaises(n_exc.IpAddressGenerationFailure):
                self.ipam.allocate_ip_address(self.context, [], 0, 0, 0)

    def test_allocate_new_ip_address_one_v6_subnet_open(self):
        mac_address = 0
        subnet6 = dict(id=1, first_ip=self.v6_fip, last_ip=self.v6_lip,
                       cidr="feed::/104", ip_version=6,
                       next_auto_assign_ip=2,
                       ip_policy=None)
        with self._stubs(subnets=[[], [(subnet6, 0)]],
                         addresses=[None, None, None, None]):
            with self.assertRaises(n_exc.IpAddressGenerationFailure):
                self.ipam.allocate_ip_address(self.context, [], 0, 0, 0,
                                              mac_address=mac_address)

    def test_allocate_new_ip_address_no_avail_subnets(self):
        with self._stubs(subnets=[[], []],
                         addresses=[None, None, None, None]):
            with self.assertRaises(n_exc.IpAddressGenerationFailure):
                addr = []
                self.ipam.allocate_ip_address(self.context, addr, 0, 0, 0)

    def test_reallocate_deallocated_v4_ip(self):
        mac_address = 0
        expected_v6 = netaddr.IPAddress('feed::200:ff:fe00:0')
        subnet6 = dict(id=66, first_ip=self.v6_fip.value,
                       last_ip=self.v6_lip.value, cidr="feed::/104",
                       ip_version=6, next_auto_assign_ip=self.v6_fip.value + 1,
                       ip_policy=None)
        address = models.IPAddress()
        address["address"] = 4
        address["version"] = 4
        address["subnet"] = models.Subnet(cidr="0.0.0.0/24")
        address["allocated_at"] = timeutils.utcnow()
        with self._stubs(subnets=[[(subnet6, 0)]],
                         addresses=[address, None, None]) as addr_realloc:
            address = []
            self.ipam.allocate_ip_address(self.context, address, 0, 0, 0,
                                          mac_address=mac_address)
            self.assertEqual(len(address), 2)
            self.assertEqual(address[0]["address"], 4)
            self.assertEqual(address[0]["version"], 4)
            self.assertEqual(
                addr_realloc.call_args[0][1][models.IPAddress.address_type],
                "fixed")
            self.assertEqual(address[1]["address"], expected_v6.value)
            self.assertEqual(address[1]["version"], 6)
            self.assertEqual(address[1]['address_type'], 'fixed')

    def test_reallocate_deallocated_v4_with_new_v6(self):
        mac_address = 0
        subnet6 = dict(id=1, first_ip=self.v6_fip.value,
                       last_ip=self.v6_lip.value, cidr="feed::/104",
                       ip_version=6, next_auto_assign_ip=-1,
                       ip_policy=None)
        address1 = models.IPAddress()
        address1["address"] = self.v46_val
        address1["version"] = 4
        address1["subnet"] = models.Subnet(cidr="0.0.0.0/24")
        address1["allocated_at"] = timeutils.utcnow()

        with self._stubs(subnets=[[(subnet6, 0)]],
                         addresses=[address1]) as addr_realloc:
            address = []
            self.ipam.allocate_ip_address(self.context, address, 0, 0, 0,
                                          mac_address=mac_address)
            self.assertEqual(len(address), 2)
            self.assertEqual(address[0]["address"], self.v46_val)
            self.assertEqual(address[0]["version"], 4)
            self.assertEqual(
                addr_realloc.call_args[0][1][models.IPAddress.address_type],
                "fixed")

            expected_v6 = netaddr.IPAddress("feed::200:ff:fe00:0")
            self.assertEqual(address[1]["address"], expected_v6.value)
            self.assertEqual(address[1]["version"], 6)
            self.assertEqual(address[1]['address_type'], 'fixed')

    def test_allocate_gets_one_ip_but_unsatisfied_strategy_fails(self):
        port_id = "236a48ed-dca8-41a8-bb1a-6e3e8d8d687e"
        old_override = cfg.CONF.QUARK.ip_address_retry_max
        cfg.CONF.set_override('ip_address_retry_max', 1, 'QUARK')
        cfg.CONF.set_override('v6_allocation_attempts', 1, 'QUARK')

        subnet4 = dict(id=1, first_ip=0, last_ip=255,
                       cidr="0.0.0.0/24", ip_version=4,
                       next_auto_assign_ip=1,
                       ip_policy=None)

        subnet6 = dict(id=2, first_ip=self.v6_fip.value,
                       last_ip=self.v6_lip.value, cidr="feed::/104",
                       ip_version=6, next_auto_assign_ip=-2,
                       ip_policy=dict(
                           size=2,
                           exclude=[
                               models.IPPolicyCIDR(cidr="feed::/128"),
                               models.IPPolicyCIDR(
                                   cidr="feed::200:ff:fe00:0/128")]))

        with self._stubs(subnets=[[(subnet4, 0)], [(subnet6, 0)]],
                         addresses=[None, None, None, None]):
            address = []
            with self.assertRaises(n_exc.IpAddressGenerationFailure):
                self.ipam.allocate_ip_address(self.context, address, 0,
                                              port_id, 0, mac_address=0)
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
            ip_mod["allocated_at"] = timeutils.utcnow()
            ip_mod["version"] = ip_address.version

        with contextlib.nested(
            mock.patch("quark.db.models.IPPolicy.get_cidrs_ip_set"),
            mock.patch("quark.db.api.ip_address_find"),
            mock.patch("quark.db.api.ip_address_create"),
            mock.patch("quark.db.api.ip_address_update")
        ) as (policy_find, ip_address_find, ip_create, ip_update):
            policy_find.return_value = policies
            ip_address_find.return_value = ip_mod
            ip_create.return_value = ip_mod
            ip_update.return_value = ip_mod
            yield policy_find, ip_address_find, ip_create, ip_update

    def test_allocate_v6_with_mac(self):
        port_id = "945af340-ed34-4fec-8c87-853a2df492b4"
        subnet6 = dict(id=1, first_ip=0, last_ip=0,
                       cidr="feed::/104", ip_version=6,
                       next_auto_assign_ip=0,
                       ip_policy=None)
        subnet6 = models.Subnet(**subnet6)

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

            # NCP-1548 - leaving this test to show the change from sometimes
            # creating the IP address to always creating the IP address.
            self.assertEqual(0, ip_update.call_count)
            self.assertEqual(1, ip_create.call_count)

        cfg.CONF.set_override('v6_allocation_attempts', old_override, 'QUARK')

    def test_allocate_v6_with_ip_and_no_mac(self):
        fip = netaddr.IPAddress('fe80::')
        ip_address = netaddr.IPAddress("fe80::7")
        lip = netaddr.IPAddress('feed::FF:FFFF')
        port_id = "945af340-ed34-4fec-8c87-853a2df492b4"
        subnet6 = dict(id=1, first_ip=fip, last_ip=lip,
                       cidr="feed::/104", ip_version=6,
                       next_auto_assign_ip=fip, ip_policy=None)
        subnet6 = models.Subnet(**subnet6)

        with self._stubs(policies=[], ip_address=ip_address) as (
                policy_find, ip_find, ip_create, ip_update):
            a = self.ipam._allocate_from_v6_subnet(self.context, 0, subnet6,
                                                   port_id, self.reuse_after,
                                                   ip_address=ip_address)
            self.assertEqual(a['address'], ip_address.value)


class QuarkNewIPAddressAllocation(QuarkIpamBaseTest):
    @contextlib.contextmanager
    def _stubs(self, addresses=None, subnets=None):
        if not addresses:
            addresses = [None]
        self.context.session.add = mock.Mock()
        with contextlib.nested(
            mock.patch("quark.db.api.ip_address_reallocate"),
            mock.patch("quark.db.api.ip_address_reallocate_find"),
            mock.patch("quark.db.api.ip_address_find"),
            mock.patch("quark.db.api.subnet_find_ordered_by_most_full"),
            mock.patch("quark.db.api.subnet_update_next_auto_assign_ip"),
            mock.patch("quark.db.api.subnet_update_set_full"),
            mock.patch("sqlalchemy.orm.session.Session.refresh")
        ) as (addr_realloc, addr_realloc_find, addr_find,
              subnet_find, subnet_update, subnet_set_full, refresh):
            addrs = [ip_helper(a) for a in addresses]
            addr_realloc.side_effect = addrs[:1]
            addr_realloc_find.side_effect = addrs[:1]
            addr_find.side_effect = addrs[1:]

            if isinstance(subnets, list):
                subnet_find.return_value = [(subnet_helper(s), c)
                                            for s, c in subnets]
            else:
                sub_mods = []
                for sub_list in subnets:
                    sub_mod_list = []
                    if not sub_list:
                        sub_mods.append([])
                        continue
                    for sub in sub_list:
                        if sub[0]:
                            sub_mod_list.append((subnet_helper(sub[0]),
                                                sub[1]))
                        else:
                            sub_mod_list.append(sub)
                    sub_mods.append(sub_mod_list)
                subnet_find.side_effect = sub_mods

            subnet_update.return_value = 1

            def refresh_mock(sub):
                sub["next_auto_assign_ip"] += 1

            def set_full_mock(context, sub):
                sub["next_auto_assign_ip"] = -1
                return 1

            refresh.side_effect = refresh_mock
            subnet_set_full.side_effect = set_full_mock
            yield addr_realloc

    def test_allocate_new_ip_address_in_empty_subnet(self):
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

    def test_allocate_one_fixed_ipv4_address(self):
        fip = netaddr.IPAddress("10.0.0.1").value
        lip = netaddr.IPAddress("10.0.0.255").value
        subnet = dict(id=1, first_ip=fip, last_ip=lip,
                      cidr="10.0.0.0/24", ip_version=4,
                      next_auto_assign_ip=fip + 1,
                      ip_policy=None)

        with self._stubs(subnets=[(subnet, 0)], addresses=[None, None]) as (
                addr_realloc):
            address = []
            ip_address = ["10.0.0.17"]
            self.ipam.allocate_ip_address(self.context, address, 0, 0, 0,
                                          ip_addresses=ip_address,
                                          subnets=[subnet])
            self.assertEqual(len(address), 1)
            self.assertEqual(netaddr.IPAddress(address[0]['address']),
                             netaddr.IPAddress('::ffff:10.0.0.17'))
            self.assertTrue(addr_realloc.called)
            args, kwargs = addr_realloc.call_args
            self.assertTrue("deallocated" not in kwargs)

    def test_allocate_two_fixed_ipv4_addresses(self):
        fip1 = netaddr.IPAddress("192.168.0.1").value
        lip1 = netaddr.IPAddress("192.168.0.255").value
        subnet1 = dict(id=1, first_ip=fip1, last_ip=lip1,
                       cidr="192.168.0.0/24", ip_version=4,
                       next_auto_assign_ip=fip1 + 1,
                       ip_policy=None)
        fip2 = netaddr.IPAddress('10.0.0.1').value
        lip2 = netaddr.IPAddress('10.0.0.255').value
        subnet2 = dict(id=2, first_ip=fip2, last_ip=lip2,
                       cidr="10.0.0.0/24", ip_version=4,
                       next_auto_assign_ip=fip2 + 1,
                       ip_policy=None)

        with self._stubs(subnets=([(subnet1, 0)], [(subnet2, 0)]),
                         addresses=[None, None]) as addr_realloc:
            address = []
            ip_addresses = ["192.168.0.17", "10.0.0.17"]
            self.ipam.allocate_ip_address(self.context, address, 0, 0, 0,
                                          ip_addresses=ip_addresses,
                                          subnets=[subnet1, subnet2])
            self.assertEqual(len(address), 2)
            self.assertEqual(netaddr.IPAddress(address[0]['address']),
                             netaddr.IPAddress('::ffff:192.168.0.17'))
            self.assertEqual(address[0]['version'], 4)
            self.assertEqual(netaddr.IPAddress(address[1]['address']),
                             netaddr.IPAddress('::ffff:10.0.0.17'))
            self.assertEqual(address[1]['version'], 4)
            self.assertTrue(addr_realloc.called)
            args, kwargs = addr_realloc.call_args
            self.assertTrue("deallocated" not in kwargs)

    def test_allocate_one_fixed_ipv6_address(self):
        fip = netaddr.IPAddress("feed::01").value
        lip = netaddr.IPAddress("feed::ff:ffff").value
        subnet = dict(id=1, first_ip=fip, last_ip=lip,
                      cidr="feed::/104", ip_version=6,
                      next_auto_assign_ip=fip + 1,
                      ip_policy=None)

        with self._stubs(subnets=[(subnet, 0)], addresses=[None, None]) as (
                addr_realloc):
            address = []
            ip_address = ["feed::13"]
            self.ipam.allocate_ip_address(self.context, address, 0, 0, 0,
                                          ip_addresses=ip_address,
                                          subnets=[subnet])
            self.assertEqual(len(address), 1)
            self.assertEqual(netaddr.IPAddress(address[0]['address']),
                             netaddr.IPAddress('feed::13'))
            self.assertEqual(address[0]["version"], 6)
            self.assertTrue(addr_realloc.called)
            args, kwargs = addr_realloc.call_args
            self.assertTrue("deallocated" not in kwargs)

    def test_allocate_two_fixed_ipv6_addresses(self):
        fip1 = netaddr.IPAddress("feed::1").value
        lip1 = netaddr.IPAddress("feed::ff:ffff").value
        subnet1 = dict(id=1, first_ip=fip1, last_ip=lip1,
                       cidr="feed::/104", ip_version=6,
                       next_auto_assign_ip=fip1 + 1,
                       ip_policy=None)
        fip2 = netaddr.IPAddress('feef::1').value
        lip2 = netaddr.IPAddress('feef::ff:ffff').value
        subnet2 = dict(id=2, first_ip=fip2, last_ip=lip2,
                       cidr="feef::/104", ip_version=6,
                       next_auto_assign_ip=fip2 + 1,
                       ip_policy=None)

        with self._stubs(subnets=([(subnet1, 0)], [(subnet2, 0)]),
                         addresses=[None, None]) as addr_realloc:
            address = []
            ip_addresses = ["feed::13", "feef::13"]
            self.ipam.allocate_ip_address(self.context, address, 0, 0, 0,
                                          ip_addresses=ip_addresses,
                                          subnets=[subnet1, subnet2])
            self.assertEqual(len(address), 2)
            self.assertEqual(netaddr.IPAddress(address[0]['address']),
                             netaddr.IPAddress('feed::13'))
            self.assertEqual(address[0]["version"], 6)
            self.assertEqual(netaddr.IPAddress(address[1]['address']),
                             netaddr.IPAddress('feef::13'))
            self.assertEqual(address[1]["version"], 6)
            self.assertTrue(addr_realloc.called)
            args, kwargs = addr_realloc.call_args
            self.assertTrue("deallocated" not in kwargs)

    def test_allocate_one_fixed_ipv6_and_one_fixed_ipv4_address(self):
        fip1 = netaddr.IPAddress("feed::01").value
        lip1 = netaddr.IPAddress("feed::ff:ffff").value
        subnet1 = dict(id=1, first_ip=fip1, last_ip=lip1,
                       cidr="feed::/104", ip_version=6,
                       next_auto_assign_ip=fip1 + 1,
                       ip_policy=None)
        fip2 = netaddr.IPAddress('10.0.0.1').value
        lip2 = netaddr.IPAddress('10.0.0.255').value
        subnet2 = dict(id=2, first_ip=fip2, last_ip=lip2,
                       cidr="10.0.0.0/24", ip_version=4,
                       next_auto_assign_ip=fip2 + 1,
                       ip_policy=None)

        with self._stubs(subnets=([(subnet1, 0)], [(subnet2, 0)]),
                         addresses=[None, None]) as addr_realloc:
            address = []
            ip_addresses = ["feed::13", "10.0.0.17"]
            self.ipam.allocate_ip_address(self.context, address, 0, 0, 0,
                                          ip_addresses=ip_addresses,
                                          subnets=[subnet1, subnet2])
            self.assertEqual(len(address), 2)
            self.assertEqual(netaddr.IPAddress(address[0]['address']),
                             netaddr.IPAddress('feed::13'))
            self.assertEqual(address[0]["version"], 6)
            self.assertEqual(netaddr.IPAddress(address[1]['address']),
                             netaddr.IPAddress('::ffff:10.0.0.17'))
            self.assertEqual(address[1]["version"], 4)
            self.assertTrue(addr_realloc.called)
            args, kwargs = addr_realloc.call_args
            self.assertTrue("deallocated" not in kwargs)

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
        with self._stubs(subnets=subnets, addresses=[None, None]) as (
                addr_realloc):
            address = []
            self.ipam.allocate_ip_address(self.context, address, 0, 0, 0)
            self.assertEqual(address[0]["address"],
                             netaddr.IPAddress("::ffff:0.0.1.1").value)
            self.assertEqual(address[0]["subnet_id"], 2)
            self.assertEqual(address[0]['address_type'], 'fixed')
            self.assertTrue(addr_realloc.called)
            args, kwargs = addr_realloc.call_args
            self.assertTrue("deallocated" in kwargs)

    def test_allocate_ip_no_subnet_fails(self):
        with self._stubs(subnets=[]):
            with self.assertRaises(n_exc.IpAddressGenerationFailure):
                self.ipam.allocate_ip_address(self.context, [], 0, 0, 0)

    def test_allocate_ip_no_available_subnet_fails(self):
        subnet1 = dict(id=1, first_ip=0, last_ip=0, next_auto_assign_ip=0,
                       cidr="0.0.0.0/32", ip_version=4,
                       ip_policy=dict(
                           size=1,
                           exclude=[models.IPPolicyCIDR(cidr="0.0.0.0/32")]))
        with self._stubs(subnets=[(subnet1, 1)]):
            with self.assertRaises(n_exc.IpAddressGenerationFailure):
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
            self.assertEqual(address[0]['address_type'], 'fixed')

    def test_find_requested_ip_subnet(self):
        subnet1 = dict(id=1, first_ip=0, last_ip=255,
                       cidr="0.0.0.0/24", ip_version=4,
                       next_auto_assign_ip=1, ip_policy=None)
        subnets = [(subnet1, 1)]
        with self._stubs(subnets=subnets, addresses=[None, None]):
            address = []
            self.ipam.allocate_ip_address(
                self.context, address, 0, 0, 0, ip_addresses=["0.0.0.240"])
            self.assertEqual(address[0]["address"],
                             netaddr.IPAddress('::ffff:0.0.0.240').value)
            self.assertEqual(address[0]["subnet_id"], 1)
            self.assertEqual(address[0]['address_type'], 'fixed')

    def test_no_valid_subnet_for_requested_ip_fails(self):
        subnet1 = dict(id=1, first_ip=0, last_ip=255, next_auto_assign_ip=1,
                       cidr="0.0.1.0/24", ip_version=4)
        subnets = [(subnet1, 1)]
        with self._stubs(subnets=subnets, addresses=[None, None]):
            with self.assertRaises(n_exc.IpAddressGenerationFailure):
                self.ipam.allocate_ip_address(
                    self.context, [], 0, 0, 0, ip_addresses=["0.0.0.240"])

    def test_allocate_new_ip_address_with_floating_address_type(self):
        subnet = dict(id=1, first_ip=0, last_ip=255,
                      cidr="0.0.0.0/24", ip_version=4,
                      next_auto_assign_ip=0,
                      ip_policy=dict(size=1, exclude=[
                          models.IPPolicyCIDR(cidr="0.0.0.0/32")]))
        with self._stubs(subnets=[(subnet, 0)], addresses=[None, None]):
            address = []
            self.ipam.allocate_ip_address(self.context, address, 0, 0, 0,
                                          version=4,
                                          address_type='floating')
            self.assertEqual(address[0]["address_type"], 'floating')


class QuarkIPAddressAllocationTestRetries(QuarkIpamBaseTest):
    @contextlib.contextmanager
    def _stubs(self, address=None, subnets=None):
        self.context.session.add = mock.Mock()
        with contextlib.nested(
            mock.patch("quark.db.api.ip_address_find"),
            mock.patch("quark.db.api.ip_address_create"),
            mock.patch("quark.db.api.subnet_find_ordered_by_most_full"),
            mock.patch("quark.db.api.subnet_update_next_auto_assign_ip"),
            mock.patch("quark.db.api.subnet_update_set_full"),
            mock.patch("sqlalchemy.orm.session.Session.refresh")
        ) as (addr_find, addr_create, subnet_find, subnet_update,
              subnet_set_full, refresh):
            addr_find.side_effect = [None, None, None]
            addr_mods = []
            for a in address:
                if isinstance(a, dict):
                    addr_mods.append(models.IPAddress(**a))
                else:
                    addr_mods.append(a)
            addr_create.side_effect = addr_mods
            sub_mods = []
            if subnets:
                for sub, count in subnets:
                    sub_mods.append((subnet_helper(sub), count))
            subnet_find.return_value = sub_mods
            subnet_update.return_value = 1

            def refresh_mock(sub):
                sub["next_auto_assign_ip"] += 1

            def set_full_mock(context, sub):
                sub["next_auto_assign_ip"] = -1
                return 1

            refresh.side_effect = refresh_mock
            subnet_set_full.side_effect = set_full_mock
            yield sub_mods, addr_mods

    def test_allocate_allocated_ip_fails_and_retries(self):
        subnet1 = dict(id=1, first_ip=0, last_ip=255, next_auto_assign_ip=1,
                       cidr="0.0.0.0/24", ip_version=4,
                       ip_policy=None)
        subnets = [(subnet1, 1)]
        addr_found = dict(id=1,
                          address=2,
                          allocated_at=timeutils.utcnow(),
                          version=4)
        with self._stubs(subnets=subnets,
                         address=[q_exc.IPAddressRetryableFailure,
                                  addr_found]) as (sub_mods, addr_mods):
            addr = []
            self.ipam.allocate_ip_address(self.context, addr, 0, 0, 0)
            used_subnet = sub_mods[0][0]
            next_auto_v4 = netaddr.IPAddress(
                used_subnet["next_auto_assign_ip"]).ipv4()
            self.assertEqual(next_auto_v4.value, 3)
            self.assertEqual(addr[0]["address"], 2)

    def test_allocate_explicit_already_allocated_fails_and_retries(self):
        subnet1 = dict(id=1, first_ip=0, last_ip=255, next_auto_assign_ip=1,
                       cidr="0.0.0.0/24", ip_version=4,
                       ip_policy=None)
        subnets = [(subnet1, 1), (subnet1, 1)]
        addr_found = dict(id=1, address=1)
        with self._stubs(subnets=subnets,
                         address=[n_exc.IpAddressInUse,
                                  addr_found]):
            with self.assertRaises(n_exc.IpAddressInUse):
                self.ipam.allocate_ip_address(
                    self.context, [], 0, 0, 0, ip_addresses=["0.0.0.1"])

    def test_allocate_implicit_already_allocated_fails_and_retries(self):
        subnet1 = dict(id=1, first_ip=0, last_ip=255, next_auto_assign_ip=1,
                       cidr="::/64", ip_version=6,
                       ip_policy=None)
        subnets = [(subnet1, 1), (subnet1, 1)]
        addr_found = dict(id=1, address=1, version=4,
                          allocated_at=timeutils.utcnow())

        with self._stubs(
            subnets=subnets,
            address=[db_exc.DBDuplicateEntry, addr_found]) as (sub_mods,
                                                               addr_mods):
            with mock.patch("quark.ipam.generate_v6") as gv6:
                gv6.return_value = (1, 2)
                ret_addrs = []
                self.ipam.allocate_ip_address(
                    self.context, ret_addrs, 0, 0, 0,
                    mac_address=dict(address=mock.MagicMock())),
                self.assertEqual(ret_addrs, addr_mods[1:])

    def test_allocate_specific_subnet_ip_not_in_subnet_fails(self):
        subnet1 = dict(id=1, first_ip=0, last_ip=255, next_auto_assign_ip=1,
                       cidr="0.0.0.0/24", ip_version=4,
                       ip_policy=None)
        subnets = [(subnet1, 1), (subnet1, 1)]
        addr_found = dict(id=1, address=256, version=4,
                          allocated_at=timeutils.utcnow())
        with self._stubs(subnets=subnets,
                         address=[q_exc.IPAddressRetryableFailure,
                                  addr_found]) as (sub_mods, addr_mods):
            with self.assertRaises(q_exc.IPAddressNotInSubnet):
                self.ipam.allocate_ip_address(
                    self.context, [], 0, 0, 0, ip_addresses=["0.0.1.0"],
                    subnets=subnet1)

    def test_allocate_specific_subnet_unusable_fails(self):
        subnet1 = dict(id=1, first_ip=0, last_ip=255, next_auto_assign_ip=1,
                       cidr="0.0.0.0/24", ip_version=4,
                       ip_policy=None,
                       do_not_use=1)
        subnets = []
        addr_found = dict(id=1, address=256, version=4,
                          allocated_at=timeutils.utcnow())
        with self._stubs(subnets=subnets,
                         address=[q_exc.IPAddressRetryableFailure,
                                  addr_found]) as (sub_mods, addr_mods):
            with self.assertRaises(n_exc.IpAddressGenerationFailure):
                self.ipam.allocate_ip_address(
                    self.context, [], 0, 0, 0, ip_addresses=["0.0.1.0"],
                    subnets=subnet1)

    def test_allocate_last_ip_allocates(self):
        # NOTE(mdietz): test originally checked if the subnet closed. Now
        #               we're letting the next allocation take care of it
        subnet1 = dict(id=1, first_ip=0, last_ip=1, next_auto_assign_ip=1,
                       cidr="0.0.0.0/31", ip_version=4,
                       ip_policy=None)
        subnets = [(subnet1, 1)]
        addr_found = dict(id=1, address=1, version=4,
                          allocated_at=timeutils.utcnow())
        with self._stubs(subnets=subnets, address=[addr_found]) as (sub_mods,
                                                                    addr_mods):
            addr = []
            self.ipam.allocate_ip_address(self.context, addr, 0, 0, 0)
            self.assertEqual(addr[0]["address"], 1)


class QuarkIPAddressAllocateDeallocated(QuarkIpamBaseTest):
    @contextlib.contextmanager
    def _stubs(self, ip_find, subnet, address, addresses_found,
               sub_found=True):
        with contextlib.nested(
            mock.patch("quark.db.api.ip_address_reallocate"),
            mock.patch("quark.db.api.ip_address_reallocate_find"),
            mock.patch("quark.db.api.ip_address_find"),
            mock.patch("quark.db.api.ip_address_update"),
            mock.patch("quark.ipam.QuarkIpamANY._choose_available_subnet")
        ) as (addr_realloc, addr_realloc_find, addr_find, addr_update,
              choose_subnet):
            addr_mod = models.IPAddress(**address)
            subnet_mod = models.Subnet(**subnet)
            subnet_mod["next_auto_assign_ip"] = subnet["next_auto_assign_ip"]

            if ip_find:
                addr_find.return_value = addr_mod
            else:
                addr_mods = []
                for a in addresses_found:
                    if a:
                        addr_mods.append(models.IPAddress(**a))
                    else:
                        addr_mods.append(None)

                addr_realloc.side_effect = addr_mods
                addr_realloc_find.side_effect = addr_mods
                addr_find.side_effect = addr_mods
                addr_update.return_value = addr_mod
            choose_subnet.return_value = [subnet_mod]
            if not sub_found:
                choose_subnet.return_value = []
            yield choose_subnet

    def test_allocate_finds_deallocated_ip_succeeds(self):
        subnet = dict(id=1, ip_version=4, next_auto_assign_ip=0,
                      do_not_use=False,
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

    def test_allocate_finds_no_deallocated_creates_new_ip(self):
        subnet = dict(id=1, ip_version=4, next_auto_assign_ip=2,
                      cidr="0.0.0.0/24", first_ip=0, last_ip=255,
                      ip_policy=None, do_not_use=False)
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
            mock.patch("quark.db.api.subnet_find_ordered_by_most_full"),
            mock.patch("quark.db.api.subnet_update_next_auto_assign_ip"),
            mock.patch("quark.db.api.subnet_update_set_full"),
            mock.patch("sqlalchemy.orm.session.Session.refresh")
        ) as (addr_find, subnet_find, subnet_update, subnet_set_full, refresh):
            addr_find.side_effect = [ip_helper(a) for a in addresses]
            sub_mods = []
            if subnets:
                for sub, count in subnets:
                    sub_mods.append((subnet_helper(sub), count))
            subnet_find.return_value = sub_mods
            subnet_update.return_value = 1

            def refresh_mock(sub):
                sub["next_auto_assign_ip"] += 1

            def set_full_mock(context, sub):
                sub["next_auto_assign_ip"] = -1
                return 1

            refresh.side_effect = refresh_mock
            subnet_set_full.side_effect = set_full_mock
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
            with self.assertRaises(n_exc.IpAddressGenerationFailure):
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
        subnet1 = dict(id=1, first_ip=0, last_ip=255, next_auto_assign_ip=1,
                       cidr="0.0.0.0/24", ip_version=4,
                       ip_policy=dict(exclude=[
                           models.IPPolicyCIDR(cidr="0.0.0.240/32")]))
        subnets = [(subnet1, 1)]
        with self._stubs(subnets=subnets, addresses=[None, None]):
            address = []
            self.ipam.allocate_ip_address(
                self.context, address, 0, 0, 0, ip_addresses=["0.0.0.240"])
            self.assertEqual(address[0]["address"],
                             netaddr.IPAddress('::ffff:0.0.0.240').value)


class QuarkIPAddressAllocationNotifications(QuarkIpamBaseTest):
    @contextlib.contextmanager
    def _stubs(self, address, addresses=None, subnets=None, deleted_at=None):
        if not addresses:
            addresses = [None]
        with contextlib.nested(
            mock.patch("quark.db.api.ip_address_find"),
            mock.patch("quark.db.api.ip_address_create"),
            mock.patch("quark.db.api.subnet_find_ordered_by_most_full"),
            mock.patch("quark.db.api.subnet_update_next_auto_assign_ip"),
            mock.patch("sqlalchemy.orm.session.Session.refresh"),
            mock.patch("neutron.common.rpc.get_notifier"),
            mock.patch("oslo_utils.timeutils.utcnow"),
        ) as (addr_find, addr_create, subnet_find, subnet_update, refresh,
              notify, timeutils):
            addrs_found = []
            for a in addresses:
                if a:
                    addrs_found.append(models.IPAddress(**a))
                else:
                    addrs_found.append(None)
            addr_find.side_effect = addrs_found
            addr_create.return_value = models.IPAddress(**address)
            sub_mods = []
            if subnets:
                for sub, count in subnets:
                    sub_mods.append((subnet_helper(sub), count))

            subnet_find.return_value = sub_mods
            subnet_update.return_value = 1
            refresh.return_value = sub_mods
            timeutils.return_value = deleted_at
            yield notify

    def test_allocation_notification(self):
        """Tests IP allocation

        Notification payload looks like this:
            {
                'ip_type': u'fixed',
                'id': u'ee267779-e513-4132-a9ba-55148eab584f',
                'event_type': u'CREATE',
                'eventTime': u'2016-05-26T21:47:45.722735Z',
                'network_id': u'None',
                'tenant_id': u'1',
                'subnet_id': u'1',
                'public': False,
                'ip_address': u'0.0.0.0',
                'ip_version': 4
            }
            But for simplicity replaced it with mock.ANY
        """

        subnet = dict(id=1, first_ip=0, last_ip=255,
                      cidr="0.0.0.0/24", ip_version=4,
                      next_auto_assign_ip=1,
                      ip_policy=None)
        allocated_at = timeutils.utcnow()
        deallocated_at = timeutils.utcnow()
        address = dict(address=0, created_at="123", subnet_id=1,
                       address_readable="0.0.0.0", used_by_tenant_id=1,
                       version=4, allocated_at=allocated_at,
                       deallocated_at=deallocated_at,
                       address_type='fixed')
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
                "ip.add",
                mock.ANY)

    def test_deallocation_notification(self):
        addr_dict = dict(address=0, created_at="123", subnet_id=1,
                         address_readable="0.0.0.0", used_by_tenant_id=1,
                         version=4)
        address = models.IPAddress()
        address.update(addr_dict)

        port_dict = dict(ip_addresses=[address], device_id="foo")
        port = models.Port()
        port.update(port_dict)
        address["ports"] = [port]

        with self._stubs(dict(), deleted_at="456") as notify:
            self.ipam.deallocate_ips_by_port(self.context, port)
            notify.assert_called_with('network')
            self.assertEqual(notify.call_count, 2,
                             'Should have called notify twice')
            # When we deallocate an IP we must send a usage message as well
            # Verify that we called both methods. Order matters.
            call_list = [mock.call(self.context, 'ip.delete', mock.ANY),
                         mock.call(self.context, 'ip.exists', mock.ANY)]
            notify.return_value.info.assert_has_calls(call_list,
                                                      any_order=False)


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

    def test_v6_generator_no_mac_uses_3041_generator(self):
        # Use a one-time generated UUID so the output is predictable
        port_id = "945af340-ed34-4fec-8c87-853a2df492b4"
        cidr = "fe80::/120"
        ip = quark.ipam.generate_v6(None, port_id, cidr).next()
        self.assertEqual(ip,
                         netaddr.IPAddress('fe80::40c9:a95:d83a:2ffa').value)


class QuarkIpamTestSelectSubnet(QuarkIpamBaseTest):
    @contextlib.contextmanager
    def _stubs(self, subnet, count, increments=True, marks_full=True):
        with contextlib.nested(
            mock.patch("quark.db.api.subnet_find_ordered_by_most_full"),
            mock.patch("quark.db.api.subnet_update_next_auto_assign_ip"),
            mock.patch("quark.db.api.subnet_update_set_full"),
            mock.patch("sqlalchemy.orm.session.Session.refresh"),
        ) as (subnet_find, subnet_incr, subnet_set_full, refresh):
            sub_mods = []
            sub_mods.append((subnet_helper(subnet), count))

            def subnet_increment(context, sub):
                if increments:
                    sub["next_auto_assign_ip"] += 1
                    return True
                return False

            def set_full_mock(context, sub):
                if marks_full:
                    sub["next_auto_assign_ip"] = -1
                    return True
                return False

            subnet_find.return_value = sub_mods
            subnet_incr.side_effect = subnet_increment
            subnet_set_full.side_effect = set_full_mock
            yield sub_mods, refresh

    def test_select_subnet_incremement_next_auto_assign(self):
        subnet = dict(id=1, first_ip=0, last_ip=255,
                      cidr="0.0.0.0/24", ip_version=4,
                      next_auto_assign_ip=1,
                      ip_policy=None, network_id=1)
        with self._stubs(subnet, 1) as (subnets, refresh):
            s = self.ipam.select_subnet(self.context, subnet["network_id"],
                                        None, None)
            self.assertEqual(subnets[0][0], s)
            self.assertEqual(subnets[0][0]["next_auto_assign_ip"], 2)

    def test_select_subnet_increment_fails(self):
        subnet = dict(id=1, first_ip=0, last_ip=255,
                      cidr="0.0.0.0/24", ip_version=4,
                      next_auto_assign_ip=1,
                      ip_policy=None, network_id=1)
        with self._stubs(subnet, 1, increments=False) as (subnets, refresh):
            s = self.ipam.select_subnet(self.context, subnet["network_id"],
                                        None, None)
            self.assertEqual(s, None)
            self.assertEqual(subnets[0][0]["next_auto_assign_ip"], 1)

    def test_select_subnet_set_subnet_full(self):
        net = netaddr.IPNetwork("0.0.0.0/24")
        subnet = dict(id=1, first_ip=0, last_ip=net.last,
                      cidr=str(net), ip_version=4,
                      next_auto_assign_ip=net.last + 1,
                      ip_policy=None, network_id=1)
        with self._stubs(subnet, net.size, increments=False) as (subnets,
                                                                 refresh):
            s = self.ipam.select_subnet(self.context, subnet["network_id"],
                                        None, None)
            self.assertIsNone(s)
            self.assertEqual(subnets[0][0]["next_auto_assign_ip"], -1)

    def test_select_subnet_set_full_already_full(self):
        net = netaddr.IPNetwork("0.0.0.0/24")
        subnet = dict(id=1, first_ip=0, last_ip=net.last,
                      cidr=str(net), ip_version=4,
                      next_auto_assign_ip=net.last + 1,
                      ip_policy=None, network_id=1)
        with self._stubs(subnet, net.size, marks_full=False) as (subnets,
                                                                 refresh):
            s = self.ipam.select_subnet(self.context, subnet["network_id"],
                                        None, None)
            self.assertEqual(None, s)
            self.assertFalse(refresh.called)

    def test_select_subnet_set_subnet_full_because_policies(self):
        net = netaddr.IPNetwork("0.0.0.0/24")
        subnet = dict(id=1, first_ip=0, last_ip=net.last,
                      cidr=str(net), ip_version=4, network_id=1,
                      next_auto_assign_ip=net.last + 1,
                      ip_policy=dict(size=1, exclude=[
                          models.IPPolicyCIDR(cidr="0.0.0.0/24")]))

        with self._stubs(subnet, net.size) as (subnets, refresh):
            s = self.ipam.select_subnet(self.context, subnet["network_id"],
                                        None, None)
            self.assertEqual(None, s)
            # NCP-1480: refactoring combined some duplicate code into a path
            # that already refreshes. Some tests were seeing stale data when
            # the refresh wasn't always called, so I chose to always refresh
            # rather than conditionally fix it.
            self.assertTrue(refresh.called)
            self.assertEqual(subnets[0][0]["next_auto_assign_ip"], -1)


class QuarkIpamTestSelectSubnetLocking(QuarkIpamBaseTest):
    @contextlib.contextmanager
    def _stubs(self, subnet, count, increments=True, marks_full=True):
        with contextlib.nested(
            mock.patch("quark.db.api.subnet_find_ordered_by_most_full"),
            mock.patch("quark.db.api.subnet_update_next_auto_assign_ip"),
            mock.patch("quark.db.api.subnet_update_set_full"),
            mock.patch("sqlalchemy.orm.session.Session.refresh"),
        ) as (subnet_find, subnet_incr, subnet_set_full, refresh):
            sub_mods = []
            sub_mods.append((subnet_helper(subnet), count))

            def subnet_increment(context, sub):
                if increments:
                    sub["next_auto_assign_ip"] += 1
                    return True
                return False

            def set_full_mock(context, sub):
                if marks_full:
                    sub["next_auto_assign_ip"] = -1
                    return True
                return False

            subnet_find.return_value = sub_mods
            subnet_incr.side_effect = subnet_increment
            subnet_set_full.side_effect = set_full_mock
            cfg.CONF.set_override('ipam_select_subnet_v6_locking', False,
                                  'QUARK')
            yield subnet_find
            cfg.CONF.set_override('ipam_select_subnet_v6_locking', True,
                                  'QUARK')

    def test_select_subnet_v6_does_not_lock(self):
        subnet = dict(id=1, first_ip=0, last_ip=18446744073709551615L,
                      cidr="::0/64", ip_version=6,
                      next_auto_assign_ip=1,
                      ip_policy=None, network_id=1)
        with self._stubs(subnet, 1) as subnet_find:
            self.ipam.select_subnet(self.context, subnet["network_id"],
                                    None, None, ip_version=6)
            subnet_find.assert_called_with(self.context, 1, lock_subnets=False,
                                           subnet_id=None, scope="all",
                                           segment_id=None, ip_version=6)

    def test_select_subnet_v4_locks(self):
        subnet = dict(id=1, first_ip=0, last_ip=255,
                      cidr="0.0.0.0/24", ip_version=4,
                      next_auto_assign_ip=1,
                      ip_policy=None, network_id=1)
        with self._stubs(subnet, 1) as subnet_find:
            self.ipam.select_subnet(self.context, subnet["network_id"],
                                    None, None, ip_version=4)
            subnet_find.assert_called_with(self.context, 1, lock_subnets=True,
                                           subnet_id=None, scope="all",
                                           segment_id=None, ip_version=4)


class QuarkIpamTestLog(test_base.TestBase):
    def test_ipam_log_entry_success_flagging(self):
        log = quark.ipam.QuarkIPAMLog()
        entry1 = log.make_entry("test1")
        entry2 = log.make_entry("test1")
        entry3 = log.make_entry("test2")
        entry4 = log.make_entry("test2")
        entry1.failed()
        self.assertFalse(entry1.success)
        entry2.failed()
        self.assertFalse(entry2.success)
        entry3.failed()
        self.assertFalse(entry3.success)
        self.assertTrue(entry4.success)

    def test_ipam_log_entry_timing(self):
        log = quark.ipam.QuarkIPAMLog()
        entry1 = log.make_entry("test1")
        w = 10 / 1000.0
        t = 0.005
        time.sleep(w)
        entry1.end()
        time_taken = entry1.get_time()
        self.assertTrue(time_taken < w + t and time_taken > w - t)

    def test_ipam_main_log_success(self):
        log = quark.ipam.QuarkIPAMLog()
        self.assertTrue(log.success)
        log.failed()
        self.assertFalse(log.success)

    def test_ipam_main_log_cumulative(self):
        patcher = mock.patch("quark.ipam.QuarkIPAMLog._output")
        output = patcher.start()
        self.addCleanup(patcher.stop)

        log = quark.ipam.QuarkIPAMLog()
        entry1 = log.make_entry("test1")
        w = 10 / 1000.0
        time.sleep(w)
        entry1.end()
        time.sleep(w)
        entry2 = log.make_entry("test1")
        entry2.end()
        log.end()
        tot = entry1.get_time() + entry2.get_time()
        output.assert_called_with(True, tot, 0, 2)

    def test_ipam_main_log_outputs_at_end(self):
        patcher = mock.patch("quark.ipam.QuarkIPAMLog._output")
        output = patcher.start()
        self.addCleanup(patcher.stop)

        log = quark.ipam.QuarkIPAMLog()
        entry1 = log.make_entry("test1")
        entry1.end()
        entry2 = log.make_entry("test1")
        entry2.end()
        self.assertFalse(output.called)
        log.end()
        self.assertTrue(output.called)

    def test_ipam_logged_decorator(self):
        patcher = mock.patch("quark.ipam.QuarkIPAMLog._output")
        output = patcher.start()
        self.addCleanup(patcher.stop)

        def ok(not_self, **kwargs):
            self.assertIn('ipam_log', kwargs)
            return

        def fail(not_self, **kwargs):
            log = kwargs.get('ipam_log')
            log.failed()
            raise Exception("Catch me!")

        quark.ipam.ipam_logged(ok)(None)
        self.assertTrue(output.called)
        output.assert_called_with(True, 0, 0, 0)
        output.reset_mock()

        try:
            quark.ipam.ipam_logged(fail)(None)
        except Exception:
            self.assertTrue(output.called)
            output.assert_called_with(False, 0, 0, 0)


class QuarkIpamTestIpAddressFailure(test_base.TestBase):
    def setUp(self):
        super(QuarkIpamTestIpAddressFailure, self).setUp()
        strategy = {"00000000-0000-0000-0000-000000000000":
                    {"bridge": "publicnet",
                     "subnets": {"4": "public_v4",
                                 "6": "public_v6"}},
                    "11111111-1111-1111-1111-111111111111":
                    {"bridge": "servicenet",
                     "subnets": {"4": "private_v4",
                                 "6": "private_v6"}}}
        strategy_json = json.dumps(strategy)
        quark.ipam.STRATEGY = network_strategy.JSONStrategy(strategy_json)

    def test_ip_failure_provider_net(self):
        net_id = "00000000-0000-0000-0000-000000000000"
        with self.assertRaises(q_exc.ProviderNetworkOutOfIps):
            raise quark.ipam.ip_address_failure(net_id)

    def test_ip_failure_tenant_net(self):
        net_id = "8f6555ca-fbe7-49db-8240-1cb84202c1f7"
        with self.assertRaises(n_exc.IpAddressGenerationFailure):
            raise quark.ipam.ip_address_failure(net_id)


class IronicIpamTestSelectSubnet(QuarkIpamBaseTest):

    def setUp(self):
        super(IronicIpamTestSelectSubnet, self).setUp()
        self.ipam = quark.ipam.IronicIpamANY()

    @contextlib.contextmanager
    def _stubs(self, subnet, count, increments=True, marks_full=True):
        with contextlib.nested(
            mock.patch("quark.db.api.subnet_find_unused"),
            mock.patch("quark.db.api.subnet_update_next_auto_assign_ip"),
            mock.patch("quark.db.api.subnet_update_set_full"),
            mock.patch("sqlalchemy.orm.session.Session.refresh"),
        ) as (subnet_find, subnet_incr, subnet_set_full, refresh):
            sub_mods = []
            sub_mods.append((subnet_helper(subnet), count))

            def subnet_increment(context, sub):
                if increments:
                    sub["next_auto_assign_ip"] += 1
                    return True
                return False

            def set_full_mock(context, sub):
                if marks_full:
                    sub["next_auto_assign_ip"] = -1
                    return True
                return False

            subnet_find.return_value = sub_mods
            subnet_incr.side_effect = subnet_increment
            subnet_set_full.side_effect = set_full_mock
            yield sub_mods, subnet_find, refresh

    def test_select_subnet_returns_unused(self):
        subnet = dict(id=1, first_ip=2, last_ip=2, next_auto_assign_ip=2,
                      cidr="0.0.0.0/30", ip_version=4, network_id=1,
                      ip_policy=dict(size=3, exclude=[
                          models.IPPolicyCIDR(cidr="0.0.0.4/32"),
                          models.IPPolicyCIDR(cidr="0.0.0.0/31")]))

        with self._stubs(subnet, 0) as (subnets, subnet_find, refresh):
            s = self.ipam.select_subnet(self.context, subnet["network_id"],
                                        None, None)
            self.assertEqual(s, subnets[0][0])

    def test_select_subnet_does_not_return_used(self):
        subnet = dict(id=1, first_ip=2, last_ip=2, next_auto_assign_ip=2,
                      cidr="0.0.0.0/30", ip_version=4, network_id=1,
                      ip_policy=dict(exclude=[
                          models.IPPolicyCIDR(cidr="0.0.0.4/32"),
                          models.IPPolicyCIDR(cidr="0.0.0.0/31")]))

        with self._stubs(subnet, 1) as (subnets, subnet_find, refresh):
            s = self.ipam.select_subnet(self.context, subnet["network_id"],
                                        None, None)
            self.assertEqual(s, None)

    def test_select_subnet_v4_locks(self):
        subnet = dict(id=1, first_ip=0, last_ip=18446744073709551615L,
                      cidr="::0/64", ip_version=6,
                      next_auto_assign_ip=1,
                      ip_policy=None, network_id=1)
        with self._stubs(subnet, 0) as (subnets, subnet_find, refresh):
            self.ipam.select_subnet(self.context, subnet["network_id"],
                                    None, None, ip_version=6)
            subnet_find.assert_called_with(self.context, 1, lock_subnets=True,
                                           subnet_id=None, scope="all",
                                           segment_id=None, ip_version=6)

    def test_select_subnet_v6_locks(self):
        subnet = dict(id=1, first_ip=0, last_ip=18446744073709551615L,
                      cidr="::0/64", ip_version=6,
                      next_auto_assign_ip=1,
                      ip_policy=None, network_id=1)
        with self._stubs(subnet, 0) as (subnets, subnet_find, refresh):
            self.ipam.select_subnet(self.context, subnet["network_id"],
                                    None, None, ip_version=6)
            subnet_find.assert_called_with(self.context, 1, lock_subnets=True,
                                           subnet_id=None, scope="all",
                                           segment_id=None, ip_version=6)
