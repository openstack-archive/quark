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


class QuarkIPAddressAllocate(QuarkIpamBaseFunctionalTest):
    @contextlib.contextmanager
    def _stubs(self, network, subnet):
        self.ipam = quark.ipam.QuarkIpamANY()
        with self.context.session.begin():
            next_ip = subnet.pop("next_auto_assign_ip", 0)
            net_mod = db_api.network_create(self.context, **network)
            subnet["network"] = net_mod
            sub_mod = db_api.subnet_create(self.context, **subnet)
            # NOTE(asadoughi): update after cidr constructor has been invoked
            db_api.subnet_update(self.context,
                                 sub_mod,
                                 next_auto_assign_ip=next_ip)
        yield net_mod
        with self.context.session.begin():
            db_api.subnet_delete(self.context, sub_mod)
            db_api.network_delete(self.context, net_mod)

    def test_allocate_finds_no_deallocated_creates_new_ip(self):
        network = dict(name="public", tenant_id="fake")
        ipnet = netaddr.IPNetwork("0.0.0.0/24")
        next_ip = ipnet.ipv6().first + 2
        subnet = dict(id=1, cidr="0.0.0.0/24", next_auto_assign_ip=next_ip,
                      ip_policy=None, tenant_id="fake")
        with self._stubs(network, subnet) as net:
            ipaddress = []
            self.ipam.allocate_ip_address(self.context, ipaddress,
                                          net["id"], 0, 0)
            self.assertIsNotNone(ipaddress[0]['id'])
            self.assertEqual(ipaddress[0]['address'], 281470681743362)
            self.assertEqual(ipaddress[0]['version'], 4)
            self.assertEqual(ipaddress[0]['used_by_tenant_id'], "fake")


class QuarkIPAddressFindReallocatable(QuarkIpamBaseFunctionalTest):
    @contextlib.contextmanager
    def _stubs(self, network, subnet):
        self.ipam = quark.ipam.QuarkIpamANY()
        with self.context.session.begin():
            next_ip = subnet.pop("next_auto_assign_ip", 0)
            net_mod = db_api.network_create(self.context, **network)
            subnet["network"] = net_mod
            sub_mod = db_api.subnet_create(self.context, **subnet)
            # NOTE(asadoughi): update after cidr constructor has been invoked
            db_api.subnet_update(self.context,
                                 sub_mod,
                                 next_auto_assign_ip=next_ip)
        yield net_mod

    def test_find_reallocatable_ips_does_not_raise(self):
        """Regression testing

        A patch recently introduced a bug wherein addressses
        could not be returned to the ip_address_find call in
        attempt_to_reallocate_ip. Adding this test to prevent
        a future regression.
        """

        network = dict(name="public", tenant_id="fake")
        ipnet = netaddr.IPNetwork("0.0.0.0/24")
        next_ip = ipnet.ipv6().first + 2
        subnet = dict(id=1, cidr="0.0.0.0/24", next_auto_assign_ip=next_ip,
                      ip_policy=None, tenant_id="fake")

        with self._stubs(network, subnet) as net:
            ip_kwargs = {
                "network_id": net["id"], "reuse_after": 14400,
                "deallocated": True, "scope": db_api.ONE,
                "lock_mode": True, "version": 4,
                "order_by": "address"}

            try:
                db_api.ip_address_find(self.context, **ip_kwargs)
            except Exception:
                self.fail("This should not have raised")


class QuarkIPAddressAllocateWithFullSubnetsNotMarkedAsFull(
        QuarkIpamBaseFunctionalTest):
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
                next_ip = model['subnet'].pop("next_auto_assign_ip", 0)
                sub_mod = db_api.subnet_create(self.context, **model['subnet'])
                # NOTE(amir): update after cidr constructor has been invoked
                db_api.subnet_update(self.context,
                                     sub_mod,
                                     next_auto_assign_ip=next_ip)
        yield net_mod

    def _create_models(self, subnet_cidr, ip_version, next_ip):
        models = {}
        net = netaddr.IPNetwork(subnet_cidr)
        first = str(netaddr.IPAddress(net.first)) + "/32"
        last = str(netaddr.IPAddress(net.last)) + "/32"
        models['ip_policy'] = dict(name='testpolicy',
                                   description='blah',
                                   exclude=[first, last])
        models["subnet"] = dict(cidr=subnet_cidr,
                                next_auto_assign_ip=next_ip,
                                tenant_id='fake',
                                do_not_use=False)
        return models

    def test_subnets_get_marked_as_full_retroactively(self):
        models = []
        models.append(self._create_models(
            "0.0.0.0/31",
            4,
            netaddr.IPNetwork("0.0.0.0/31").ipv6().last))
        models.append(self._create_models(
            "1.1.1.0/31",
            4,
            netaddr.IPNetwork("1.1.1.0/31").ipv6().last))
        models.append(self._create_models(
            "2.2.2.0/30",
            4,
            netaddr.IPNetwork("2.2.2.0/30").ipv6().first))

        with self._fixtures(models) as net:
            ipaddress = []
            self.ipam.allocate_ip_address(self.context, ipaddress,
                                          net['id'], 0, 0)
            self.assertEqual(ipaddress[0].version, 4)
            self.assertEqual(ipaddress[0].address_readable, "2.2.2.1")

            with self.context.session.begin():
                subnets = db_api.subnet_find(self.context, None, None, None,
                                             False).all()
                self.assertEqual(len(subnets), 3)

                full_subnets = [s for s in subnets
                                if s.next_auto_assign_ip == -1]
                self.assertEqual(len(full_subnets), 2)
                available_subnets = list(set(full_subnets) ^ set(subnets))
                self.assertEqual(len(available_subnets), 1)
                self.assertEqual(available_subnets[0].cidr, "2.2.2.0/30")
                self.assertEqual(available_subnets[0].next_auto_assign_ip,
                                 netaddr.IPAddress("2.2.2.2").ipv6().value)


class QuarkIPAddressReallocateDeallocated(QuarkIpamBaseFunctionalTest):
    @contextlib.contextmanager
    def _stubs(self, network, subnets, ipam_strategy):
        self.ipam = ipam_strategy
        with self.context.session.begin():
            net_mod = db_api.network_create(self.context, **network)
            next_ip = []
            sub_mod = []
            for sub in subnets:
                next_ip.append(sub.pop("next_auto_assign_ip", 0))
                sub["network"] = net_mod
                sub_mod.append(db_api.subnet_create(self.context, **sub))
            for sub, ip_next in zip(sub_mod, next_ip):
                # NOTE(asadoughi): update after cidr constructor has been
                # invoked
                db_api.subnet_update(self.context,
                                     sub,
                                     next_auto_assign_ip=ip_next)
        yield net_mod, sub_mod
        with self.context.session.begin():
            for sub in sub_mod:
                db_api.subnet_delete(self.context, sub)
            db_api.network_delete(self.context, net_mod)

    def test_allocate_deallocated_ips_ipam_both_req(self):
        network = dict(name="public", tenant_id="fake")
        ipnet = netaddr.IPNetwork("0.0.0.0/24")
        next_ip = ipnet.ipv6().first + 2
        subnet1 = dict(id=1, cidr="0.0.0.0/24", next_auto_assign_ip=next_ip,
                       ip_policy=None, tenant_id="fake", version=4)
        subnet2 = dict(id=2, cidr="fe80::dead:beef/64",
                       next_auto_assign_ip=next_ip,
                       ip_policy=None, tenant_id="fake", version=6)
        subnets = [subnet1, subnet2]
        ipam_strategy = quark.ipam.QuarkIpamBOTHREQ()
        with self._stubs(network, subnets, ipam_strategy) as (net, sub):
            ipaddress = []
            self.ipam.allocate_ip_address(self.context, ipaddress,
                                          net["id"], 0, 0, subnets=[1, 2])
            self.assertEqual(len(ipaddress), 2)
            for ip in ipaddress:
                self.assertTrue(ip['version'] in [4, 6])
                self.assertIsNotNone(ip['id'])
                self.assertEqual(ip['used_by_tenant_id'], 'fake')
            # Deallocate both given ip's
            for ip in ipaddress:
                self.ipam.deallocate_ip_address(self.context, ip)

            # Now attempt to reallocate
            self.ipam.allocate_ip_address(self.context, ipaddress,
                                          net["id"], 0, 0, subnets=[1, 2])
