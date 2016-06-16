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
# License for# the specific language governing permissions and limitations
#  under the License.

import mock
import netaddr
from neutron_lib import exceptions as n_exc
from oslo_config import cfg

import contextlib

from quark.db import api as db_api
import quark.ipam
# import below necessary if file run by itself
from quark import plugin  # noqa
import quark.plugin_modules.ip_policies as policy_api
import quark.plugin_modules.networks as network_api
import quark.plugin_modules.subnets as subnet_api
from quark.tests.functional.base import BaseFunctionalTest

CONF = cfg.CONF


class QuarkGetSubnets(BaseFunctionalTest):
    @contextlib.contextmanager
    def _stubs(self, network, subnet):
        self.ipam = quark.ipam.QuarkIpamANY()
        with self.context.session.begin():
            net_mod = db_api.network_create(self.context, **network)
            subnet["network"] = net_mod
            sub1 = db_api.subnet_create(self.context, **subnet)
            subnet["id"] = 2
            sub2 = db_api.subnet_create(self.context, do_not_use=True,
                                        **subnet)
        yield net_mod, sub1, sub2

    def test_get_subnet_do_not_use_not_returned(self):
        network = dict(name="public", tenant_id="fake", network_plugin="BASE")
        subnet = dict(id=1, ip_version=4, next_auto_assign_ip=2,
                      cidr="0.0.0.0/24", first_ip=0, last_ip=255,
                      ip_policy=None, tenant_id="fake")
        with self._stubs(network, subnet) as (net, sub1, sub2):
            subnets = db_api.subnet_find_ordered_by_most_full(self.context,
                                                              net["id"]).all()
            self.assertEqual(len(subnets), 1)
            self.assertEqual(subnets[0][0]["id"], "1")


class QuarkGetSubnetsFromPlugin(BaseFunctionalTest):
    @contextlib.contextmanager
    def _stubs(self, network, subnet):
        self.ipam = quark.ipam.QuarkIpamANY()
        with contextlib.nested(mock.patch("neutron.common.rpc.get_notifier")):
            net = network_api.create_network(self.context, network)
            subnet['subnet']['network_id'] = net['id']
            sub1 = subnet_api.create_subnet(self.context, subnet)
            yield net, sub1

    def test_toggle_ip_policy_id_from_subnet_view(self):
        cidr = "192.168.1.0/24"
        ip_network = netaddr.IPNetwork(cidr)
        network = dict(name="public", tenant_id="fake", network_plugin="BASE")
        network = {"network": network}
        subnet = dict(id=1, ip_version=4, next_auto_assign_ip=2,
                      cidr=cidr, first_ip=ip_network.first,
                      last_ip=ip_network.last, ip_policy=None,
                      tenant_id="fake")
        subnet = {"subnet": subnet}
        original = cfg.CONF.QUARK.show_subnet_ip_policy_id
        with self._stubs(network, subnet) as (net, sub1):
            cfg.CONF.set_override('show_subnet_ip_policy_id', True, "QUARK")
            subnet = subnet_api.get_subnet(self.context, 1)
            self.assertTrue('ip_policy_id' in subnet)
            cfg.CONF.set_override('show_subnet_ip_policy_id', False, "QUARK")
            subnet = subnet_api.get_subnet(self.context, 1)
            self.assertFalse('ip_policy_id' in subnet)
        cfg.CONF.set_override('show_subnet_ip_policy_id', original, "QUARK")


class QuarkCreateSubnets(BaseFunctionalTest):
    @contextlib.contextmanager
    def _stubs(self, network, subnet):
        self.ipam = quark.ipam.QuarkIpamANY()
        with contextlib.nested(mock.patch("neutron.common.rpc.get_notifier")):
            net = network_api.create_network(self.context, network)
            subnet['subnet']['network_id'] = net['id']
            sub1 = subnet_api.create_subnet(self.context, subnet)
            yield net, sub1

    def test_create_allocation_pools_over_quota_fail(self):
        original_pool_quota = cfg.CONF.QUOTAS.quota_alloc_pools_per_subnet
        cidr = "1.1.1.0/8"
        ip_network = netaddr.IPNetwork(cidr)
        network = dict(name="public", tenant_id="fake", network_plugin="BASE")
        network = {"network": network}
        pools = [{"start": "1.0.1.2", "end": "1.0.2.0"},
                 {"start": "1.0.2.2", "end": "1.0.3.0"}]
        subnet = dict(id=1, ip_version=4, next_auto_assign_ip=2,
                      cidr=cidr, first_ip=ip_network.first,
                      last_ip=ip_network.last, ip_policy=None,
                      tenant_id="fake", allocation_pools=pools)
        subnet = {"subnet": subnet}
        with self.assertRaises(n_exc.OverQuota):
            cfg.CONF.set_override('quota_alloc_pools_per_subnet', 1, "QUOTAS")
            with self._stubs(network, subnet) as (net, sub):
                self.assertTrue(sub)
        cfg.CONF.set_override('quota_alloc_pools_per_subnet',
                              original_pool_quota, "QUOTAS")

    def test_create_allocation_pools_under_quota_pass(self):
        original_pool_quota = cfg.CONF.QUOTAS.quota_alloc_pools_per_subnet
        cidr = "1.1.1.0/8"
        ip_network = netaddr.IPNetwork(cidr)
        network = dict(name="public", tenant_id="fake", network_plugin="BASE")
        network = {"network": network}
        pools = [{"start": "1.0.1.2", "end": "1.0.2.0"}]
        subnet = dict(id=1, ip_version=4, next_auto_assign_ip=2,
                      cidr=cidr, first_ip=ip_network.first,
                      last_ip=ip_network.last, ip_policy=None,
                      tenant_id="fake", allocation_pools=pools)
        subnet = {"subnet": subnet}
        cfg.CONF.set_override('quota_alloc_pools_per_subnet', 1, "QUOTAS")
        with self._stubs(network, subnet) as (net, sub):
            self.assertTrue(sub)
        cfg.CONF.set_override('quota_alloc_pools_per_subnet',
                              original_pool_quota, "QUOTAS")

    def test_create_allocation_pools_empty(self):
        cidr = "192.168.1.0/24"
        ip_network = netaddr.IPNetwork(cidr)
        network = dict(name="public", tenant_id="fake", network_plugin="BASE")
        network = {"network": network}
        pools = []
        subnet = dict(id=1, ip_version=4, next_auto_assign_ip=2,
                      cidr=cidr, first_ip=ip_network.first,
                      last_ip=ip_network.last, ip_policy=None,
                      tenant_id="fake", allocation_pools=pools)
        subnet = {"subnet": subnet}
        with self._stubs(network, subnet) as (net, sub1):
            self.assertEqual(sub1["allocation_pools"], [])

    def test_create_allocation_pools_none(self):
        cidr = "192.168.1.0/24"
        ip_network = netaddr.IPNetwork(cidr)
        network = dict(name="public", tenant_id="fake", network_plugin="BASE")
        network = {"network": network}
        pools = None
        subnet = dict(id=1, ip_version=4, next_auto_assign_ip=2,
                      cidr=cidr, first_ip=ip_network.first,
                      last_ip=ip_network.last, ip_policy=None,
                      tenant_id="fake", allocation_pools=pools)
        subnet = {"subnet": subnet}
        with self._stubs(network, subnet) as (net, sub1):
            self.assertEqual(sub1["allocation_pools"],
                             [dict(start="192.168.1.1", end="192.168.1.254")])

    def test_create_allocation_pools_full(self):
        cidr = "192.168.1.0/24"
        ip_network = netaddr.IPNetwork(cidr)
        network = dict(name="public", tenant_id="fake", network_plugin="BASE")
        network = {"network": network}
        pools = [dict(start="192.168.1.0", end="192.168.1.255")]
        subnet = dict(id=1, ip_version=4, next_auto_assign_ip=2,
                      cidr=cidr, first_ip=ip_network.first,
                      last_ip=ip_network.last, ip_policy=None,
                      tenant_id="fake", allocation_pools=pools)
        subnet = {"subnet": subnet}
        with self._stubs(network, subnet) as (net, sub1):
            self.assertEqual(sub1["allocation_pools"],
                             [dict(start="192.168.1.1", end="192.168.1.254")])

    def test_create_ipv6_subnet_with_multiple_allocation_pools(self):
        cidr = "fd00:243:e319::/64"
        ip_network = netaddr.IPNetwork(cidr)
        network = dict(name="public", tenant_id="fake", network_plugin="BASE")
        network = {"network": network}
        pools = [{'start': 'fd00:243:e319::64', 'end': 'fd00:243:e319::384'},
                 {'start': 'fd00:243:e319::3e8', 'end': 'fd00:243:e319::76c'},
                 {'start': 'fd00:243:e319::7d0', 'end': 'fd00:243:e319::b54'}]
        next_auto_assign_ip = ip_network.first + 1
        subnet = dict(id=1, ip_versino=6,
                      next_auto_assign_ip=next_auto_assign_ip,
                      cidr=cidr, first_ip=ip_network.first,
                      last_ip=ip_network.last, ip_policy=None,
                      tenant_id="fake", allocation_pools=pools)
        subnet = {"subnet": subnet}
        with self._stubs(network, subnet) as (net, sub1):
            self.assertEqual(sub1["allocation_pools"], pools)


class QuarkUpdateSubnets(BaseFunctionalTest):

    def setUp(self):
        super(QuarkUpdateSubnets, self).setUp()
        self.og = CONF.QUARK.allow_allocation_pool_update
        self.og1 = CONF.QUARK.allow_allocation_pool_growth
        CONF.set_override('allow_allocation_pool_update', True, 'QUARK')
        CONF.set_override('allow_allocation_pool_growth', True, 'QUARK')

    def tearDown(self):
        super(QuarkUpdateSubnets, self).tearDown()
        CONF.set_override('allow_allocation_pool_update', self.og, 'QUARK')
        CONF.set_override('allow_allocation_pool_growth', self.og1, 'QUARK')

    @contextlib.contextmanager
    def _stubs(self, network, subnet):
        self.ipam = quark.ipam.QuarkIpamANY()
        with contextlib.nested(mock.patch("neutron.common.rpc.get_notifier")):
            net = network_api.create_network(self.context, network)
            subnet['subnet']['network_id'] = net['id']
            sub1 = subnet_api.create_subnet(self.context, subnet)
            yield net, sub1

    def test_update_allocation_pools(self):
        cidr = "192.168.1.0/24"
        ip_network = netaddr.IPNetwork(cidr)
        network = dict(name="public", tenant_id="fake", network_plugin="BASE")
        network = {"network": network}
        subnet = dict(id=1, ip_version=4, next_auto_assign_ip=2,
                      cidr=cidr, first_ip=ip_network.first,
                      last_ip=ip_network.last, ip_policy=None,
                      tenant_id="fake")
        subnet = {"subnet": subnet}
        with self._stubs(network, subnet) as (net, sub1):
            subnet = subnet_api.get_subnet(self.context, 1)
            start_pools = subnet['allocation_pools']
            new_pools = [
                [dict(start='192.168.1.10', end='192.168.1.50')],
                [dict(start='192.168.1.5', end='192.168.1.25')],
                [dict(start='192.168.1.50', end='192.168.1.51')],
                [dict(start='192.168.1.50', end='192.168.1.51'),
                    dict(start='192.168.1.100', end='192.168.1.250')],
                [dict(start='192.168.1.50', end='192.168.1.51')],
                start_pools,
            ]
            prev_pool = start_pools
            for pool in new_pools:
                subnet_update = {"subnet": dict(allocation_pools=pool)}
                subnet = subnet_api.update_subnet(self.context, 1,
                                                  subnet_update)
                self.assertNotEqual(prev_pool, subnet['allocation_pools'])
                self.assertEqual(pool, subnet['allocation_pools'])
                policies = policy_api.get_ip_policies(self.context)
                self.assertEqual(1, len(policies))
                policy = policies[0]
                ip_set = netaddr.IPSet()
                for ip in policy['exclude']:
                    ip_set.add(netaddr.IPNetwork(ip))
                for extent in pool:
                    for ip in netaddr.IPRange(extent['start'], extent['end']):
                        self.assertFalse(ip in ip_set)
                prev_pool = pool

    def test_allow_allocation_pool_growth(self):
        CONF.set_override('allow_allocation_pool_growth', True, 'QUARK')
        cidr = "192.168.1.0/24"
        ip_network = netaddr.IPNetwork(cidr)
        network = dict(name="public", tenant_id="fake", network_plugin="BASE")
        network = {"network": network}
        pool = [dict(start='192.168.1.15', end='192.168.1.30')]
        subnet = dict(id=1, ip_version=4, next_auto_assign_ip=2,
                      cidr=cidr, first_ip=ip_network.first,
                      last_ip=ip_network.last, ip_policy=None,
                      allocation_pools=pool, tenant_id="fake")
        subnet = {"subnet": subnet}
        with self._stubs(network, subnet) as (net, sub1):
            subnet = subnet_api.get_subnet(self.context, 1)
            start_pools = subnet['allocation_pools']
            new_pool = [dict(start='192.168.1.10', end='192.168.1.50')]

            subnet_update = {"subnet": dict(allocation_pools=new_pool)}
            subnet = subnet_api.update_subnet(self.context, 1,
                                              subnet_update)
            self.assertNotEqual(start_pools, subnet['allocation_pools'])
            self.assertEqual(new_pool, subnet['allocation_pools'])
            policies = policy_api.get_ip_policies(self.context)
            self.assertEqual(1, len(policies))
            policy = policies[0]
            ip_set = netaddr.IPSet()
            for ip in policy['exclude']:
                ip_set.add(netaddr.IPNetwork(ip))
            for extent in new_pool:
                for ip in netaddr.IPRange(extent['start'], extent['end']):
                    self.assertFalse(ip in ip_set)

            start_ip_set = netaddr.IPSet()
            for rng in start_pools:
                start_ip_set.add(netaddr.IPRange(rng['start'], rng['end']))

            new_ip_set = netaddr.IPSet()
            for rng in subnet['allocation_pools']:
                new_ip_set.add(netaddr.IPRange(rng['start'], rng['end']))

            self.assertTrue(start_ip_set | new_ip_set != start_ip_set)

    def test_do_not_allow_allocation_pool_growth(self):
        CONF.set_override('allow_allocation_pool_growth', False, 'QUARK')
        cidr = "192.168.1.0/24"
        ip_network = netaddr.IPNetwork(cidr)
        network = dict(name="public", tenant_id="fake", network_plugin="BASE")
        network = {"network": network}
        pool = [dict(start='192.168.1.15', end='192.168.1.30')]
        subnet = dict(id=1, ip_version=4, next_auto_assign_ip=2,
                      cidr=cidr, first_ip=ip_network.first,
                      last_ip=ip_network.last, ip_policy=None,
                      allocation_pools=pool, tenant_id="fake")
        subnet = {"subnet": subnet}
        with self._stubs(network, subnet) as (net, sub1):
            subnet = subnet_api.get_subnet(self.context, 1)
            start_pools = subnet['allocation_pools']
            new_pool = [dict(start='192.168.1.10', end='192.168.1.50')]

            start_ip_set = netaddr.IPSet()
            for rng in start_pools:
                start_ip_set.add(netaddr.IPRange(rng['start'], rng['end']))

            new_ip_set = netaddr.IPSet()
            for rng in new_pool:
                new_ip_set.add(netaddr.IPRange(rng['start'], rng['end']))

            self.assertTrue(start_ip_set | new_ip_set != start_ip_set)

            subnet_update = {"subnet": dict(allocation_pools=new_pool)}
            with self.assertRaises(n_exc.BadRequest):
                subnet = subnet_api.update_subnet(self.context, 1,
                                                  subnet_update)

    def _test_allow_allocation_pool_identity(self, conf_flag):
        CONF.set_override('allow_allocation_pool_growth', conf_flag, 'QUARK')
        cidr = "192.168.1.0/24"
        ip_network = netaddr.IPNetwork(cidr)
        network = dict(name="public", tenant_id="fake", network_plugin="BASE")
        network = {"network": network}
        pool = [dict(start='192.168.1.15', end='192.168.1.30')]
        subnet = dict(id=1, ip_version=4, next_auto_assign_ip=2,
                      cidr=cidr, first_ip=ip_network.first,
                      last_ip=ip_network.last, ip_policy=None,
                      allocation_pools=pool, tenant_id="fake")
        subnet = {"subnet": subnet}
        with self._stubs(network, subnet) as (net, sub1):
            subnet = subnet_api.get_subnet(self.context, 1)
            start_pools = subnet['allocation_pools']
            new_pool = [dict(start='192.168.1.15', end='192.168.1.30')]

            start_ip_set = netaddr.IPSet()
            for rng in start_pools:
                start_ip_set.add(netaddr.IPRange(rng['start'], rng['end']))

            new_ip_set = netaddr.IPSet()
            for rng in new_pool:
                new_ip_set.add(netaddr.IPRange(rng['start'], rng['end']))

            self.assertTrue(start_ip_set == new_ip_set)

            subnet_update = {"subnet": dict(allocation_pools=new_pool)}
            subnet = subnet_api.update_subnet(self.context, 1, subnet_update)
            self.assertEqual(start_pools, subnet['allocation_pools'])
            self.assertEqual(new_pool, subnet['allocation_pools'])

    def test_allow_allocation_pool_identity_when_growth_false(self):
        self._test_allow_allocation_pool_identity(False)

    def test_allow_allocation_pool_identity_when_growth_true(self):
        self._test_allow_allocation_pool_identity(True)
