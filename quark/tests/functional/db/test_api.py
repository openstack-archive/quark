# Copyright (c) 2013 OpenStack Foundation
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
from neutron.common import rpc

from quark.db import api as db_api
import quark.ipam
from quark.tests.functional.base import BaseFunctionalTest


class QuarkIpamBaseFunctionalTest(BaseFunctionalTest):
    def setUp(self):
        super(QuarkIpamBaseFunctionalTest, self).setUp()

        patcher = mock.patch("neutron.common.rpc.oslo_messaging")
        patcher.start()
        self.addCleanup(patcher.stop)
        rpc.init(mock.MagicMock())


class QuarkFindSubnetAllocationCount(QuarkIpamBaseFunctionalTest):
    @contextlib.contextmanager
    def _fixtures(self, models):

        self.ipam = quark.ipam.QuarkIpamANY()
        net = dict(name="public", tenant_id='fake')
        net_mod = db_api.network_create(self.context, **net)
        with self.context.session.begin():
            for model in models:
                policy_mod = db_api.ip_policy_create(
                    self.context, **model['ip_policy'])
                model['subnet']["network"] = net_mod
                model['subnet']["ip_policy"] = policy_mod
                db_api.subnet_create(self.context, **model['subnet'])
        yield net_mod

    def _create_models(self, subnet_cidr, ip_version, next_ip):
        models = {}
        net = netaddr.IPNetwork(subnet_cidr)
        first = str(netaddr.IPAddress(net.first))
        last = str(netaddr.IPAddress(net.last))
        models['ip_policy'] = dict(name='testpolicy',
                                   description='blah',
                                   exclude=[first, last],
                                   size=2)
        models["subnet"] = dict(cidr=subnet_cidr,
                                first_ip=net.first,
                                last_ip=net.last,
                                next_auto_assign_ip=next_ip,
                                tenant_id='fake',
                                do_not_use=False)
        return models

    def _create_ip_address(self, ip_address, ip_version, subnet_cidr, net_id):
        with self.context.session.begin():
            subnet = db_api.subnet_find(self.context, None, False, None, None,
                                        cidr=subnet_cidr).all()
            ip = dict(subnet_id=subnet[0].id,
                      network_id=net_id,
                      version=ip_version,
                      address=netaddr.IPAddress(ip_address))
            db_api.ip_address_create(self.context, **ip)

    def test_ordering_subnets_find_allocation_counts_when_count_equal(self):
        models = []
        cidrs = ["0.0.0.0/31", "1.1.1.0/31", "2.2.2.0/31"]
        for cidr in cidrs:
            last = netaddr.IPNetwork(cidr).last
            models.append(self._create_models(cidr, 4, last))

        with self._fixtures(models) as net:
            subnets = db_api.subnet_find_ordered_by_most_full(
                self.context, net['id'], segment_id=None,
                scope=db_api.ALL).all()
            self.assertEqual(len(subnets), 3)
            for subnet in subnets:
                self.assertIn(subnet[0]["cidr"], cidrs)

            subnets = db_api.subnet_find_ordered_by_least_full(
                self.context, net['id'], segment_id=None,
                scope=db_api.ALL).all()
            self.assertEqual(len(subnets), 3)
            for subnet in subnets:
                self.assertIn(subnet[0]["cidr"], cidrs)

    def test_ordering_subnets_find_allocation_counts_when_counts_unequal(self):
        models = []
        cidrs = ["0.0.0.0/31", "1.1.1.0/31", "2.2.2.0/30"]
        for cidr in cidrs:
            last = netaddr.IPNetwork(cidr).last
            models.append(self._create_models(cidr, 4, last))

        with self._fixtures(models) as net:
            self._create_ip_address("2.2.2.2", 4, "2.2.2.0/30", net["id"])

            subnets_with_same_ips_used = ["0.0.0.0/31", "1.1.1.0/31"]
            subnets = db_api.subnet_find_ordered_by_most_full(
                self.context, net['id'], segment_id=None,
                scope=db_api.ALL).all()
            self.assertEqual(len(subnets), 3)
            self.assertIn(subnets[0][0].cidr, subnets_with_same_ips_used)
            self.assertEqual(subnets[0][1], 0)
            self.assertIn(subnets[1][0].cidr, subnets_with_same_ips_used)
            self.assertEqual(subnets[1][1], 0)
            self.assertEqual(subnets[2][0].cidr, "2.2.2.0/30")
            self.assertEqual(subnets[2][1], 1)

            subnets = db_api.subnet_find_ordered_by_least_full(
                self.context, net['id'], segment_id=None,
                scope=db_api.ALL).all()
            self.assertEqual(len(subnets), 3)
            self.assertEqual(subnets[0][0].cidr, "2.2.2.0/30")
            self.assertEqual(subnets[0][1], 1)
            self.assertIn(subnets[1][0].cidr, subnets_with_same_ips_used)
            self.assertEqual(subnets[1][1], 0)
            self.assertIn(subnets[2][0].cidr, subnets_with_same_ips_used)
            self.assertEqual(subnets[2][1], 0)

    def test_ordering_subnets_find_allocc_when_counts_unequal_size_equal(self):
        models = []
        cidrs = ["0.0.0.0/31", "1.1.1.0/31", "2.2.2.0/31"]
        for cidr in cidrs:
            last = netaddr.IPNetwork(cidr).last
            models.append(self._create_models(cidr, 4, last))

        with self._fixtures(models) as net:
            self._create_ip_address("2.2.2.1", 4, "2.2.2.0/31", net["id"])
            self._create_ip_address("2.2.2.2", 4, "2.2.2.0/31", net["id"])
            self._create_ip_address("1.1.1.1", 4, "1.1.1.0/31", net["id"])

            subnets = db_api.subnet_find_ordered_by_most_full(
                self.context, net['id'], segment_id=None,
                scope=db_api.ALL).all()
            self.assertEqual(len(subnets), 3)
            self.assertEqual(subnets[0][0].cidr, "2.2.2.0/31")
            self.assertEqual(subnets[0][1], 2)
            self.assertEqual(subnets[1][0].cidr, "1.1.1.0/31")
            self.assertEqual(subnets[1][1], 1)
            self.assertEqual(subnets[2][0].cidr, "0.0.0.0/31")
            self.assertEqual(subnets[2][1], 0)

            subnets = db_api.subnet_find_ordered_by_least_full(
                self.context, net['id'], segment_id=None,
                scope=db_api.ALL).all()
            self.assertEqual(len(subnets), 3)
            self.assertEqual(subnets[0][0].cidr, "0.0.0.0/31")
            self.assertEqual(subnets[0][1], 0)
            self.assertEqual(subnets[1][0].cidr, "1.1.1.0/31")
            self.assertEqual(subnets[1][1], 1)
            self.assertEqual(subnets[2][0].cidr, "2.2.2.0/31")
            self.assertEqual(subnets[2][1], 2)

    def test_ordering_subnets_ip_version(self):
        """Order by ip_version primarily.

        Order by ip_version primarily, even when IPv4 is less full than IPv6
        subnet.
        """
        cidr4 = "0.0.0.0/30"  # 2 bits
        last4 = netaddr.IPNetwork(cidr4).last
        cidr6 = "fffc::/127"  # 1 bits
        last6 = netaddr.IPNetwork(cidr6).last
        with self._fixtures([
            self._create_models(cidr4, 4, last4),
            self._create_models(cidr6, 6, last6)
        ]) as net:
            subnets = db_api.subnet_find_ordered_by_most_full(
                self.context, net['id'], segment_id=None,
                scope=db_api.ALL).all()
            self.assertEqual(subnets[0][0].ip_version, 4)
            self.assertEqual(subnets[1][0].ip_version, 6)

            subnets = db_api.subnet_find_ordered_by_least_full(
                self.context, net['id'], segment_id=None,
                scope=db_api.ALL).all()
            self.assertEqual(subnets[0][0].ip_version, 4)
            self.assertEqual(subnets[1][0].ip_version, 6)

    def test_ordering_subnets_find_unused(self):
        models = []
        cidrsv4 = ["0.0.0.0/31", "1.1.1.0/31", "2.2.2.0/31"]
        cidrsv6 = ["fffc::/127", "fffd::/127"]

        for version, cidrs in [(4, cidrsv4), (6, cidrsv6)]:
            for cidr in cidrs:
                last = netaddr.IPNetwork(cidr).last
                models.append(self._create_models(cidr, version, last))

        with self._fixtures(models) as net:
            self._create_ip_address("2.2.2.1", 4, "2.2.2.0/31", net["id"])
            self._create_ip_address("2.2.2.2", 4, "2.2.2.0/31", net["id"])
            self._create_ip_address("1.1.1.1", 4, "1.1.1.0/31", net["id"])
            self._create_ip_address("fffc::1", 6, "fffc::/127", net["id"])

            subnets = db_api.subnet_find_unused(
                self.context, net['id'], segment_id=None,
                scope=db_api.ALL).all()
            self.assertEqual(len(subnets), 2)
            self.assertEqual(subnets[0][0].cidr, "0.0.0.0/31")
            self.assertEqual(subnets[0][1], 0)
            self.assertEqual(subnets[1][0].cidr, "fffd::/127")
            self.assertEqual(subnets[1][1], 0)

    def test_subnet_set_full(self):
        cidr4 = "0.0.0.0/30"  # 2 bits
        net4 = netaddr.IPNetwork(cidr4)
        with self._fixtures([
            self._create_models(cidr4, 4, net4[0])
        ]) as net:
            subnet = db_api.subnet_find(self.context, network_id=net['id'],
                                        scope=db_api.ALL)[0]
            with self.context.session.begin():
                updated = db_api.subnet_update_set_full(self.context, subnet)
                self.context.session.refresh(subnet)
                self.assertTrue(updated)
                self.assertEqual(subnet["next_auto_assign_ip"], -1)

    def test_subnet_update_next_auto_assign_ip(self):
        cidr4 = "0.0.0.0/30"  # 2 bits
        net4 = netaddr.IPNetwork(cidr4)
        with self._fixtures([
            self._create_models(cidr4, 4, net4[0])
        ]) as net:
            subnet = db_api.subnet_find(self.context, network_id=net['id'],
                                        scope=db_api.ALL)[0]
            with self.context.session.begin():
                updated = db_api.subnet_update_next_auto_assign_ip(
                    self.context, subnet)
                self.context.session.refresh(subnet)
                self.assertTrue(updated)
                self.assertEqual(
                    netaddr.IPAddress(subnet["next_auto_assign_ip"]).ipv4(),
                    net4[1])


class QuarkFindMacAddressRangeAllocationCount(QuarkIpamBaseFunctionalTest):
    @contextlib.contextmanager
    def _fixtures(self, mac_ranges):
        self.ipam = quark.ipam.QuarkIpamANY()
        for mar in mac_ranges:
            with self.context.session.begin():
                db_api.mac_address_range_create(self.context,
                                                **mar)
        yield

    def test_mac_address_ranges(self):
        mr1_mac = netaddr.EUI("AA:AA:AA:00:00:00")
        mr1 = {"cidr": "AA:AA:AA/24", "do_not_use": False,
               "first_address": mr1_mac.value,
               "last_address": netaddr.EUI("AA:AA:AA:FF:FF:FF").value,
               "next_auto_assign_mac": mr1_mac.value}
        with self._fixtures([mr1]):
            with self.context.session.begin():
                ranges = db_api.mac_address_range_find_allocation_counts(
                    self.context)
                self.assertTrue(ranges[0]["cidr"], mr1["cidr"])

    def test_mac_address_ranges_do_not_use_returns_nothing(self):
        mr1_mac = netaddr.EUI("AA:AA:AA:00:00:00")
        mr1 = {"cidr": "AA:AA:AA/24", "do_not_use": True,
               "first_address": mr1_mac.value,
               "last_address": netaddr.EUI("AA:AA:AA:FF:FF:FF").value,
               "next_auto_assign_mac": mr1_mac.value}

        with self._fixtures([mr1]):
            with self.context.session.begin():
                ranges = db_api.mac_address_range_find_allocation_counts(
                    self.context)
                self.assertTrue(ranges is None)

    def test_mac_address_ranges_do_not_use_returns_on_use_forbidden_rage(self):
        mr1_mac = netaddr.EUI("AA:AA:AA:00:00:00")
        mr1 = {"cidr": "AA:AA:AA/24", "do_not_use": True,
               "first_address": mr1_mac.value,
               "last_address": netaddr.EUI("AA:AA:AA:FF:FF:FF").value,
               "next_auto_assign_mac": mr1_mac.value}

        with self._fixtures([mr1]):
            with self.context.session.begin():
                ranges = db_api.mac_address_range_find_allocation_counts(
                    self.context, use_forbidden_mac_range=True)
                self.assertTrue(ranges[0]["cidr"], mr1["cidr"])
