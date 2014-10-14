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

        patcher = mock.patch("neutron.common.rpc.messaging")
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
            subnet = db_api.subnet_find(self.context, cidr=subnet_cidr).all()
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
