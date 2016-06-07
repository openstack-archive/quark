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
from neutron_lib import exceptions as n_exc

from quark.db import api as db_api
from quark.db import models
import quark.ipam

# import below necessary if file run by itself
from quark import plugin  # noqa
import quark.plugin_modules.ip_policies as policy_api
import quark.plugin_modules.networks as network_api
import quark.plugin_modules.subnets as subnet_api
from quark.tests.functional.base import BaseFunctionalTest

from oslo_config import cfg


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


class TestQuarkIpamAllocateFromV6Subnet(QuarkIpamBaseFunctionalTest):
    @contextlib.contextmanager
    def _stubs(self, network, subnet, ip_policy):
        self.ipam = quark.ipam.QuarkIpamANY()
        with contextlib.nested(mock.patch("neutron.common.rpc.get_notifier")):
            net = network_api.create_network(self.context, network)
            subnet['subnet']['network_id'] = net['id']
            sub = subnet_api.create_subnet(self.context, subnet)
            ipp = policy_api.update_ip_policy(self.context,
                                              sub["ip_policy_id"], ip_policy)
            sub = subnet_api.get_subnet(self.context, sub['id'])
        yield net, sub, ipp

    def test_allocate_v6_with_mac_fails_policy_raises(self):
        cidr = netaddr.IPNetwork("fe80::dead:beef/64")
        allocation_pool = [{"start": cidr[-4], "end": cidr[-2]}]
        subnet = dict(allocation_pools=allocation_pool,
                      cidr="fe80::dead:beef/64", ip_version=6,
                      next_auto_assign_ip=0, tenant_id="fake")
        subnet = {"subnet": subnet}

        network = dict(name="public", tenant_id="fake", network_plugin="BASE")
        network = {"network": network}

        ip_policy = {"exclude": ["fe80::dead:beef/64"]}
        ip_policy = {"ip_policy": ip_policy}

        mac = models.MacAddress()
        mac["address"] = netaddr.EUI("AA:BB:CC:DD:EE:FF")

        old_override = cfg.CONF.QUARK.v6_allocation_attempts
        cfg.CONF.set_override('v6_allocation_attempts', 1, 'QUARK')

        with self._stubs(network, subnet, ip_policy) as (net, sub, ipp):
            with self.assertRaises(n_exc.IpAddressGenerationFailure):
                self.ipam.allocate_ip_address(self.context, [], net["id"], 0,
                                              0, subnets=[sub["id"]])
        cfg.CONF.set_override('v6_allocation_attempts', old_override, 'QUARK')


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


class QuarkIPAddressReallocateAllocated(QuarkIpamBaseFunctionalTest):
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

    def test_allocate_ipv4_throws_cannot_reallocate_allocated_ip(self):
        network = dict(name="public", tenant_id="fake")
        ipnet = netaddr.IPNetwork("0.0.0.0/24")
        next_ip = ipnet.ipv6().first + 2
        subnet = dict(id=1, cidr="0.0.0.0/24", next_auto_assign_ip=next_ip,
                      ip_policy=None, tenant_id="fake")
        subnets = [subnet]
        ipam_strategy = quark.ipam.QuarkIpamANY()
        with self._stubs(network, subnets, ipam_strategy) as (net, sub):
            ipaddress = []
            self.ipam.allocate_ip_address(self.context, ipaddress,
                                          net["id"], 0, 0)
            self.assertIsNotNone(ipaddress[0]['id'])
            self.assertEqual(ipaddress[0]['address'], 281470681743362)
            self.assertEqual(ipaddress[0]['version'], 4)
            self.assertEqual(ipaddress[0]['used_by_tenant_id'], "fake")
            # Attempt to allocate the same IP
            with self.assertRaises(n_exc.IpAddressInUse):
                allocated_ip = [ipaddress[0]['address']]
                self.ipam.allocate_ip_address(self.context, [],
                                              net["id"], 0, 0,
                                              ip_addresses=allocated_ip)

    def test_allocate_ipv6_throws_cannot_reallocate_allocated_ip(self):
        network = dict(name="public", tenant_id="fake")
        ipnet = netaddr.IPNetwork("0.0.0.0/24")
        next_ip = ipnet.ipv6().first + 2
        subnet = dict(id=1, cidr="fe80::dead:beef/64",
                      next_auto_assign_ip=next_ip,
                      ip_policy=None, tenant_id="fake")
        subnets = [subnet]
        ipam_strategy = quark.ipam.QuarkIpamANY()
        with self._stubs(network, subnets, ipam_strategy) as (net, sub):
            ipaddress = []
            self.ipam.allocate_ip_address(self.context, ipaddress,
                                          net["id"], 0, 0, version=6)
            self.assertIsNotNone(ipaddress[0]['id'])
            self.assertEqual(ipaddress[0]['version'], 6)
            self.assertEqual(ipaddress[0]['used_by_tenant_id'], "fake")
            # Attempt to allocate the same IP
            with self.assertRaises(n_exc.IpAddressInUse):
                allocated_ip = [ipaddress[0]['address']]
                self.ipam.allocate_ip_address(self.context, [],
                                              net["id"], 0, 0,
                                              ip_addresses=allocated_ip)

    def test_allocate_both_v4_v6_throws_cannot_reallocate_allocated_ip(self):
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
            # Attempt to allocate the same IP
            with self.assertRaises(n_exc.IpAddressInUse):
                allocated_ip = [ip['address_readable'] for ip in ipaddress]
                self.ipam.allocate_ip_address(self.context, [],
                                              net["id"], 0, 0,
                                              ip_addresses=allocated_ip,
                                              subnets=[1, 2])


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
