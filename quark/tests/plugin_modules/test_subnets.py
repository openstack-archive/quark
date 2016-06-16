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
import copy
from datetime import datetime
import json
import time
import uuid

import mock
from neutron.api.v2 import attributes as neutron_attrs
from neutron.common import exceptions as n_exc_ext
from neutron_lib import exceptions as n_exc
from oslo_config import cfg

from quark.db import api as db_api
from quark.db import models
from quark import exceptions as q_exc
from quark import network_strategy
from quark import plugin_views
from quark.tests import test_quark_plugin


class TestQuarkGetSubnetCount(test_quark_plugin.TestQuarkPlugin):
    def test_get_subnet_count(self):
        """This isn't really testable."""
        with mock.patch("quark.db.api.subnet_count_all"):
            self.plugin.get_subnets_count(self.context, {})


class TestQuarkGetSubnets(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, subnets=None, routes=None):
        if routes is None:
            routes = []
        route_models = []
        for route in routes:
            r = models.Route()
            r.update(route)
            route_models.append(r)

        if isinstance(subnets, list):
            subnet_models = []
            for subnet in subnets:
                s_dict = subnet.copy()
                s_dict["routes"] = route_models
                s = models.Subnet(network=models.Network())
                s.update(s_dict)
                subnet_models.append(s)
        elif subnets:
            mod = models.Subnet(network=models.Network())
            mod.update(subnets)
            mod["routes"] = route_models
            subnet_models = mod
        else:
            subnet_models = None

        with mock.patch("quark.db.api.subnet_find") as subnet_find:
            subnet_find.return_value = subnet_models
            yield

    def test_subnets_list(self):
        subnet_id = str(uuid.uuid4())
        route = dict(id=1, cidr="0.0.0.0/0", gateway="192.168.0.1")

        subnet = dict(id=subnet_id, network_id=1, name=subnet_id,
                      tenant_id=self.context.tenant_id, ip_version=4,
                      cidr="192.168.0.0/24", gateway_ip="192.168.0.1",
                      dns_nameservers=[],
                      enable_dhcp=None)

        with self._stubs(subnets=[subnet], routes=[route]):
            res = self.plugin.get_subnets(self.context, None, None, None, {},
                                          {})
            # Compare routes separately
            routes = res[0].pop("host_routes")
            for key in subnet.keys():
                self.assertEqual(res[0][key], subnet[key])
            self.assertEqual(len(routes), 0)

    def test_subnets_list_two_default_routes_shows_last_one(self):
        subnet_id = str(uuid.uuid4())
        route = dict(id=1, cidr="0.0.0.0/0", gateway="192.168.0.1")
        route2 = dict(id=1, cidr="0.0.0.0/0", gateway="192.168.0.2")

        subnet = dict(id=subnet_id, network_id=1, name=subnet_id,
                      tenant_id=self.context.tenant_id, ip_version=4,
                      cidr="192.168.0.0/24", gateway_ip="192.168.0.1",
                      dns_nameservers=[],
                      enable_dhcp=None)

        with self._stubs(subnets=[subnet], routes=[route, route2]):
            res = self.plugin.get_subnets(self.context, None, None, None, {},
                                          {})

            # Don't want to test that LOG.info is called but we can
            # know the case is covered by checking the gateway is the one
            # we expect it to be
            self.assertEqual(res[0]["gateway_ip"], "192.168.0.2")
            self.assertEqual(len(res[0]["host_routes"]), 0)

    def test_subnet_show_fail(self):
        with self._stubs():
            with self.assertRaises(n_exc.SubnetNotFound):
                self.plugin.get_subnet(self.context, 1)

    def test_subnet_show(self):
        subnet_id = str(uuid.uuid4())
        route = dict(id=1, cidr="0.0.0.0/0", gateway="192.168.0.1",
                     subnet_id=subnet_id)

        subnet = dict(id=subnet_id, network_id=1, name=subnet_id,
                      tenant_id=self.context.tenant_id, ip_version=4,
                      cidr="192.168.0.0/24", gateway_ip="192.168.0.1",
                      dns_nameservers=[],
                      enable_dhcp=None)

        with self._stubs(subnets=subnet, routes=[route]):
            res = self.plugin.get_subnet(self.context, subnet_id)

            # Compare routes separately
            routes = res.pop("host_routes")
            for key in subnet.keys():
                self.assertEqual(res[key], subnet[key])
            self.assertEqual(len(routes), 0)


class TestQuarkGetSubnetsHideAllocPools(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, subnets=None):
        if isinstance(subnets, list):
            subnet_models = []
            for subnet in subnets:
                s_dict = subnet.copy()
                s = models.Subnet(network=models.Network())
                s.update(s_dict)
                subnet_models.append(s)

        cfg.CONF.set_override('show_allocation_pools', False, "QUARK")
        with mock.patch("quark.db.api.subnet_find") as subnet_find:
            subnet_find.return_value = subnet_models
            yield
        cfg.CONF.set_override('show_allocation_pools', True, "QUARK")

    def test_subnets_list(self):
        subnet_id = str(uuid.uuid4())

        subnet = dict(id=subnet_id, network_id=1, name=subnet_id,
                      tenant_id=self.context.tenant_id, ip_version=4,
                      cidr="192.168.0.0/24", gateway_ip="192.168.0.1",
                      dns_nameservers=[],
                      enable_dhcp=None)

        with self._stubs(subnets=[subnet]):
            res = self.plugin.get_subnets(self.context, None, None, None, {},
                                          {})
            self.assertEqual(res[0]["allocation_pools"], [])


class TestQuarkCreateSubnetOverlapping(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, subnets=None):
        if subnets is None:
            subnets = []
        subnet_models = []
        for subnet in subnets:
            s = models.Subnet()
            s.update(subnet)
            subnet_models.append(s)
        network = models.Network()
        network.update(dict(id=1, subnets=subnet_models))
        with contextlib.nested(
            mock.patch("quark.db.api.network_find"),
            mock.patch("quark.db.api.subnet_find"),
            mock.patch("quark.db.api.subnet_create"),
            mock.patch("neutron.common.rpc.get_notifier")
        ) as (net_find, subnet_find, subnet_create, get_notifier):
            net_find.return_value = network
            subnet_find.return_value = subnet_models
            subnet_create.return_value = models.Subnet(
                network=models.Network(),
                cidr="192.168.1.1/24")
            yield subnet_create

    def test_create_subnet_overlapping_true(self):
        cfg.CONF.set_override('allow_overlapping_ips', True)
        with self._stubs() as subnet_create:
            s = dict(subnet=dict(
                gateway_ip=neutron_attrs.ATTR_NOT_SPECIFIED,
                dns_nameservers=neutron_attrs.ATTR_NOT_SPECIFIED,
                cidr="192.168.1.1/8",
                network_id=1))
            self.plugin.create_subnet(self.context, s)
            self.assertEqual(subnet_create.call_count, 1)

    def test_create_subnet_overlapping_false(self):
        cfg.CONF.set_override('allow_overlapping_ips', False)
        with self._stubs() as subnet_create:
            s = dict(subnet=dict(
                gateway_ip=neutron_attrs.ATTR_NOT_SPECIFIED,
                dns_nameservers=neutron_attrs.ATTR_NOT_SPECIFIED,
                cidr="192.168.1.1/8",
                network_id=1))
            self.plugin.create_subnet(self.context, s)
            self.assertEqual(subnet_create.call_count, 1)

    def test_create_subnet_overlapping_conflict(self):
        cfg.CONF.set_override('allow_overlapping_ips', False)
        with self._stubs(subnets=[dict(cidr="192.168.10.1/24")]):
            with self.assertRaises(n_exc.InvalidInput):
                s = dict(subnet=dict(cidr="192.168.1.1/8",
                                     network_id=1))
                self.plugin.create_subnet(self.context, s)


class TestQuarkCreateSubnetAllocationPools(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, subnet):
        s = models.Subnet(network=models.Network(id=1, subnets=[]))
        allocation_pools = subnet.pop("allocation_pools", None)
        s.update(subnet)
        if allocation_pools is not None:
            subnet["allocation_pools"] = allocation_pools

        def _allocation_pools_mock():
            if allocation_pools is not None:
                return mock.patch.object(models.Subnet, "allocation_pools")
            return mock.MagicMock()

        with contextlib.nested(
            mock.patch("quark.db.api.network_find"),
            mock.patch("quark.db.api.subnet_find"),
            mock.patch("quark.db.api.subnet_create"),
            mock.patch("neutron.common.rpc.get_notifier"),
            _allocation_pools_mock(),
        ) as (net_find, subnet_find, subnet_create, get_notifier,
              alloc_pools_method):
            net_find.return_value = s["network"]
            subnet_find.return_value = []
            subnet_create.return_value = s
            alloc_pools_method.__get__ = mock.Mock(
                return_value=allocation_pools)
            yield subnet_create

    def setUp(self):
        super(TestQuarkCreateSubnetAllocationPools, self).setUp()

    def tearDown(self):
        super(TestQuarkCreateSubnetAllocationPools, self).tearDown()

    def test_create_subnet_allocation_pools_zero(self):
        s = dict(subnet=dict(
            cidr="192.168.1.1/24",
            network_id=1))
        with self._stubs(s["subnet"]) as (subnet_create):
            resp = self.plugin.create_subnet(self.context, s)
            self.assertEqual(subnet_create.call_count, 1)
            self.assertEqual(resp["allocation_pools"],
                             [dict(start="192.168.1.1", end="192.168.1.254")])

    def test_create_subnet_allocation_pools_zero_v6(self):
        s = dict(subnet=dict(
            cidr="2607:f0d0:1002:51::0/64",
            network_id=1))
        with self._stubs(s["subnet"]) as (subnet_create):
            resp = self.plugin.create_subnet(self.context, s)
            self.assertEqual(subnet_create.call_count, 1)
            self.assertEqual(
                resp["allocation_pools"],
                [dict(start="2607:f0d0:1002:51::1",
                      end="2607:f0d0:1002:51:ffff:ffff:ffff:fffe")])

    def test_create_subnet_allocation_pools_one(self):
        pools = [dict(start="192.168.1.10", end="192.168.1.20")]
        s = dict(subnet=dict(
            allocation_pools=pools,
            cidr="192.168.1.1/24",
            network_id=1))
        with self._stubs(s["subnet"]) as (subnet_create):
            resp = self.plugin.create_subnet(self.context, s)
            self.assertEqual(subnet_create.call_count, 1)
            self.assertEqual(resp["allocation_pools"], pools)

    def test_create_subnet_allocation_pools_gateway_conflict(self):
        pools = [dict(start="192.168.1.1", end="192.168.1.20")]
        s = dict(subnet=dict(allocation_pools=pools,
                             cidr="192.168.1.1/24",
                             gateway_ip="192.168.1.1",
                             network_id=1))
        with self._stubs(s["subnet"]):
            with self.assertRaises(
                    n_exc_ext.GatewayConflictWithAllocationPools):
                self.plugin.create_subnet(self.context, s)

    def test_create_subnet_allocation_pools_invalid_outside(self):
        pools = [dict(start="192.168.0.10", end="192.168.0.20")]
        s = dict(subnet=dict(
            allocation_pools=pools,
            cidr="192.168.1.1/24",
            network_id=1))
        with self._stubs(s["subnet"]):
            with self.assertRaises(n_exc_ext.OutOfBoundsAllocationPool):
                self.plugin.create_subnet(self.context, s)

    def test_create_subnet_allocation_pools_invalid_overlaps(self):
        pools = [dict(start="192.168.0.255", end="192.168.1.20")]
        s = dict(subnet=dict(
            allocation_pools=pools,
            cidr="192.168.1.1/24",
            network_id=1))
        with self._stubs(s["subnet"]):
            with self.assertRaises(n_exc_ext.OutOfBoundsAllocationPool):
                self.plugin.create_subnet(self.context, s)

    def test_create_subnet_allocation_pools_two(self):
        pools = [dict(start="192.168.1.10", end="192.168.1.20"),
                 dict(start="192.168.1.40", end="192.168.1.50")]
        s = dict(subnet=dict(
            allocation_pools=pools,
            cidr="192.168.1.1/24",
            network_id=1))
        with self._stubs(s["subnet"]) as (subnet_create):
            resp = self.plugin.create_subnet(self.context, s)
            self.assertEqual(subnet_create.call_count, 1)
            self.assertEqual(resp["allocation_pools"], pools)

    def test_create_subnet_allocation_pools_three(self):
        pools = [dict(start="192.168.1.5", end="192.168.1.254")]
        s = dict(subnet=dict(
            allocation_pools=pools,
            ip_version=4,
            cidr="192.168.1.1/24",
            network_id=1))
        with self._stubs(s["subnet"]) as (subnet_create):
            resp = self.plugin.create_subnet(self.context, s)
            self.assertEqual(subnet_create.call_count, 1)
            self.assertEqual(resp["allocation_pools"], pools)

    def test_create_subnet_allocation_pools_four(self):
        pools = [dict(start="2607:f0d0:1002:51::a",
                 end="2607:f0d0:1002:51::ffff:fffe")]
        s = dict(subnet=dict(
            allocation_pools=pools,
            ip_version=6,
            cidr="2607:f0d0:1002:51::0/64",
            network_id=1))
        with self._stubs(s["subnet"]) as (subnet_create):
            resp = self.plugin.create_subnet(self.context, s)
            self.assertEqual(subnet_create.call_count, 1)
            self.assertEqual(resp["allocation_pools"], pools)

    def test_create_subnet_allocation_pools_empty_list(self):
        # Empty allocation_pools list yields subnet completely blocked out.
        pools = []
        s = dict(subnet=dict(
            allocation_pools=pools,
            cidr="192.168.1.1/24",
            network_id=1))
        with self._stubs(s["subnet"]) as (subnet_create):
            resp = self.plugin.create_subnet(self.context, s)
            self.assertEqual(subnet_create.call_count, 1)
            expected_pools = []
            self.assertEqual(resp["allocation_pools"], expected_pools)


# TODO(amir): Refactor the tests to test individual subnet attributes.
# * copy.deepcopy was necessary to maintain tests on keys, which is a bit ugly.
# * workaround is also in place for lame ATTR_NOT_SPECIFIED object()
class TestQuarkCreateSubnet(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, subnet=None, network=True, routes=(), dns=()):

        subnet_mod = models.Subnet(
            network=models.Network(id=1) if network else None)
        dns_ips = subnet.pop("dns_nameservers", [])
        host_routes = subnet.pop("host_routes", [])
        allocation_pools = subnet.pop("allocation_pools", None)
        subnet_mod.update(subnet)

        subnet["dns_nameservers"] = dns_ips
        subnet["host_routes"] = host_routes
        if allocation_pools is not None:
            subnet["allocation_pools"] = allocation_pools
        dns = [{"ip": x} for x in dns]
        route_models = [models.Route(**r) for r in routes]
        dns_models = [models.DNSNameserver(**d) for d in dns]

        def _allocation_pools_mock():
            if allocation_pools is not None:
                return mock.patch.object(models.Subnet, "allocation_pools")
            return mock.MagicMock()
        with contextlib.nested(
            mock.patch("quark.db.api.subnet_create"),
            mock.patch("quark.db.api.network_find"),
            mock.patch("quark.db.api.dns_create"),
            mock.patch("quark.db.api.route_create"),
            mock.patch("quark.db.api.subnet_find"),
            mock.patch("neutron.common.rpc.get_notifier"),
            _allocation_pools_mock()
        ) as (subnet_create, net_find, dns_create, route_create, subnet_find,
              get_notifier, alloc_pools_method):
            subnet_create.return_value = subnet_mod
            net_find.return_value = network
            route_create.side_effect = route_models
            dns_create.side_effect = dns_models
            alloc_pools_method.__get__ = mock.Mock(
                return_value=allocation_pools)
            yield subnet_create, dns_create, route_create

    def test_create_subnet(self):
        routes = [dict(cidr="0.0.0.0/0", gateway="0.0.0.0")]
        subnet = dict(
            subnet=dict(network_id=1,
                        tenant_id=self.context.tenant_id, ip_version=4,
                        cidr="172.16.0.0/24", gateway_ip="0.0.0.0",
                        dns_nameservers=neutron_attrs.ATTR_NOT_SPECIFIED,
                        host_routes=neutron_attrs.ATTR_NOT_SPECIFIED,
                        enable_dhcp=None))
        with self._stubs(
            subnet=subnet["subnet"],
            routes=routes
        ) as (subnet_create, dns_create, route_create):
            dns_nameservers = subnet["subnet"].pop("dns_nameservers")
            host_routes = subnet["subnet"].pop("host_routes")
            subnet_request = copy.deepcopy(subnet)
            subnet_request["subnet"]["dns_nameservers"] = dns_nameservers
            subnet_request["subnet"]["host_routes"] = host_routes
            res = self.plugin.create_subnet(self.context,
                                            subnet_request)
            self.assertEqual(subnet_create.call_count, 1)
            self.assertEqual(dns_create.call_count, 0)
            self.assertEqual(route_create.call_count, 1)
            for key in subnet["subnet"].keys():
                if key == "host_routes":
                    self.assertEqual(res[key][0]["destination"], "0.0.0.0/0")
                    self.assertEqual(res[key][0]["nexthop"], "0.0.0.0")
                else:
                    self.assertEqual(res[key], subnet["subnet"][key])
            expected_pools = [{'start': '172.16.0.1',
                              'end': '172.16.0.254'}]
            self.assertEqual(res["allocation_pools"], expected_pools)

    def test_create_subnet_v6_too_small(self):
        routes = [dict(cidr="0.0.0.0/0", gateway="0.0.0.0")]
        subnet = dict(
            subnet=dict(network_id=1,
                        tenant_id=self.context.tenant_id, ip_version=4,
                        cidr="1234::/80", gateway_ip="0.0.0.0",
                        dns_nameservers=neutron_attrs.ATTR_NOT_SPECIFIED,
                        host_routes=neutron_attrs.ATTR_NOT_SPECIFIED,
                        enable_dhcp=None))
        with self._stubs(
            subnet=subnet["subnet"],
            routes=routes
        ) as (subnet_create, dns_create, route_create):
            dns_nameservers = subnet["subnet"].pop("dns_nameservers")
            host_routes = subnet["subnet"].pop("host_routes")
            subnet_request = copy.deepcopy(subnet)
            subnet_request["subnet"]["dns_nameservers"] = dns_nameservers
            subnet_request["subnet"]["host_routes"] = host_routes
            with self.assertRaises(n_exc.InvalidInput):
                self.plugin.create_subnet(self.context, subnet_request)

    def test_create_subnet_v4_too_small(self):
        routes = [dict(cidr="0.0.0.0/0", gateway="0.0.0.0")]
        subnet = dict(
            subnet=dict(network_id=1,
                        tenant_id=self.context.tenant_id, ip_version=4,
                        cidr="192.168.0.0/31", gateway_ip="0.0.0.0",
                        dns_nameservers=neutron_attrs.ATTR_NOT_SPECIFIED,
                        host_routes=neutron_attrs.ATTR_NOT_SPECIFIED,
                        enable_dhcp=None))
        with self._stubs(
            subnet=subnet["subnet"],
            routes=routes
        ) as (subnet_create, dns_create, route_create):
            dns_nameservers = subnet["subnet"].pop("dns_nameservers")
            host_routes = subnet["subnet"].pop("host_routes")
            subnet_request = copy.deepcopy(subnet)
            subnet_request["subnet"]["dns_nameservers"] = dns_nameservers
            subnet_request["subnet"]["host_routes"] = host_routes
            with self.assertRaises(n_exc.InvalidInput):
                self.plugin.create_subnet(self.context, subnet_request)

    def test_create_subnet_not_admin_segment_id_ignored(self):
        routes = [dict(cidr="0.0.0.0/0", gateway="0.0.0.0")]
        subnet = dict(
            subnet=dict(network_id=1,
                        tenant_id=self.context.tenant_id, ip_version=4,
                        cidr="172.16.0.0/24", gateway_ip="0.0.0.0",
                        dns_nameservers=neutron_attrs.ATTR_NOT_SPECIFIED,
                        host_routes=neutron_attrs.ATTR_NOT_SPECIFIED,
                        enable_dhcp=None))
        with self._stubs(
            subnet=subnet["subnet"],
            routes=routes
        ) as (subnet_create, dns_create, route_create):
            dns_nameservers = subnet["subnet"].pop("dns_nameservers")
            host_routes = subnet["subnet"].pop("host_routes")
            subnet_request = copy.deepcopy(subnet)
            subnet_request["subnet"]["dns_nameservers"] = dns_nameservers
            subnet_request["subnet"]["host_routes"] = host_routes
            subnet_request["subnet"]["segment_id"] = "cell01"
            res = self.plugin.create_subnet(self.context,
                                            subnet_request)
            self.assertEqual(subnet_create.call_count, 1)
            self.assertTrue("segment_id" not in subnet_create.called_with)

            self.assertEqual(dns_create.call_count, 0)
            self.assertEqual(route_create.call_count, 1)
            for key in subnet["subnet"].keys():
                if key == "host_routes":
                    self.assertEqual(res[key][0]["destination"], "0.0.0.0/0")
                    self.assertEqual(res[key][0]["nexthop"], "0.0.0.0")
                else:
                    self.assertEqual(res[key], subnet["subnet"][key])

    def test_create_subnet_no_network_fails(self):
        subnet = dict(subnet=dict(network_id=1))
        with self._stubs(subnet=dict(), network=False):
            with self.assertRaises(n_exc.NetworkNotFound):
                self.plugin.create_subnet(self.context, subnet)

    def test_create_subnet_no_gateway_ip_defaults(self):
        subnet = dict(
            subnet=dict(network_id=1,
                        tenant_id=self.context.tenant_id, ip_version=4,
                        cidr="172.16.0.0/24",
                        gateway_ip=neutron_attrs.ATTR_NOT_SPECIFIED,
                        dns_nameservers=neutron_attrs.ATTR_NOT_SPECIFIED,
                        enable_dhcp=None))
        with self._stubs(
            subnet=subnet["subnet"],
            routes=[]
        ) as (subnet_create, dns_create, route_create):
            dns_nameservers = subnet["subnet"].pop("dns_nameservers")
            gateway_ip = subnet["subnet"].pop("gateway_ip")
            subnet_request = copy.deepcopy(subnet)
            subnet_request["subnet"]["dns_nameservers"] = dns_nameservers
            subnet_request["subnet"]["gateway_ip"] = gateway_ip
            res = self.plugin.create_subnet(self.context, subnet_request)
            self.assertEqual(subnet_create.call_count, 1)
            self.assertEqual(dns_create.call_count, 0)
            self.assertEqual(route_create.call_count, 0)
            for key in subnet["subnet"].keys():
                if key == "gateway_ip":
                    self.assertEqual(res[key], "172.16.0.1")
                elif key == "host_routes":
                    self.assertEqual(len(res[key]), 0)
                else:
                    self.assertEqual(res[key], subnet["subnet"][key])

    def test_create_subnet_dns_nameservers(self):
        routes = [dict(cidr="0.0.0.0/0", gateway="0.0.0.0")]
        dns_ns = ["4.2.2.1", "4.2.2.2"]
        subnet = dict(
            subnet=dict(network_id=1,
                        tenant_id=self.context.tenant_id, ip_version=4,
                        cidr="172.16.0.0/24", gateway_ip="0.0.0.0",
                        dns_nameservers=dns_ns, enable_dhcp=None))
        with self._stubs(
            subnet=subnet["subnet"],
            routes=routes,
            dns=dns_ns
        ) as (subnet_create, dns_create, route_create):
            res = self.plugin.create_subnet(self.context,
                                            copy.deepcopy(subnet))
            self.assertEqual(subnet_create.call_count, 1)
            self.assertEqual(dns_create.call_count, 2)
            self.assertEqual(route_create.call_count, 1)
            for key in subnet["subnet"].keys():
                if key == "host_routes":
                    self.assertEqual(len(res[key]), 0)
                else:
                    self.assertEqual(res[key], subnet["subnet"][key])

    def test_create_subnet_routes(self):
        routes = [dict(cidr="1.1.1.1/8", gateway="172.16.0.4"),
                  dict(cidr="0.0.0.0/0", gateway="0.0.0.0")]
        subnet = dict(
            subnet=dict(network_id=1,
                        tenant_id=self.context.tenant_id, ip_version=4,
                        cidr="172.16.0.0/24", gateway_ip="0.0.0.0",
                        dns_nameservers=neutron_attrs.ATTR_NOT_SPECIFIED,
                        host_routes=[{"destination": "1.1.1.1/8",
                                      "nexthop": "172.16.0.4"}],
                        allocation_pools=[{"start": "172.16.0.5",
                                           "end": "172.16.0.254"}],
                        enable_dhcp=None))
        with self._stubs(
            subnet=subnet["subnet"],
            routes=routes
        ) as (subnet_create, dns_create, route_create):
            dns_nameservers = subnet["subnet"].pop("dns_nameservers")
            subnet_request = copy.deepcopy(subnet)
            subnet_request["subnet"]["dns_nameservers"] = dns_nameservers
            res = self.plugin.create_subnet(self.context, subnet_request)
            self.assertEqual(subnet_create.call_count, 1)
            self.assertEqual(dns_create.call_count, 0)
            self.assertEqual(route_create.call_count, 2)
            for key in subnet["subnet"].keys():
                if key == "host_routes":
                    res_tuples = [(r["destination"], r["nexthop"])
                                  for r in res[key]]
                    self.assertIn(("1.1.1.1/8", "172.16.0.4"), res_tuples)
                    self.assertEqual(1, len(res_tuples))
                else:
                    self.assertEqual(res[key], subnet["subnet"][key])

    def test_create_subnet_default_route(self):
        routes = [dict(cidr="0.0.0.0/0", gateway="172.16.0.4")]
        subnet = dict(
            subnet=dict(network_id=1,
                        tenant_id=self.context.tenant_id, ip_version=4,
                        cidr="172.16.0.0/24",
                        gateway_ip=neutron_attrs.ATTR_NOT_SPECIFIED,
                        dns_nameservers=neutron_attrs.ATTR_NOT_SPECIFIED,
                        host_routes=[{"destination": "0.0.0.0/0",
                                      "nexthop": "172.16.0.4"}],
                        allocation_pools=[{"start": "172.16.0.5",
                                           "end": "172.16.0.254"}],
                        enable_dhcp=None))
        with self._stubs(
            subnet=subnet["subnet"],
            routes=routes
        ) as (subnet_create, dns_create, route_create):
            dns_nameservers = subnet["subnet"].pop("dns_nameservers")
            gateway_ip = subnet["subnet"].pop("gateway_ip")
            subnet_request = copy.deepcopy(subnet)
            subnet_request["subnet"]["dns_nameservers"] = dns_nameservers
            subnet_request["subnet"]["gateway_ip"] = gateway_ip
            res = self.plugin.create_subnet(self.context, subnet_request)
            self.assertEqual(subnet_create.call_count, 1)
            self.assertEqual(dns_create.call_count, 0)
            self.assertEqual(route_create.call_count, 1)
            for key in subnet["subnet"].keys():
                if key == "gateway_ip":
                    self.assertEqual(res[key], "172.16.0.4")
                elif key == "host_routes":
                    self.assertEqual(len(res[key]), 0)
                else:
                    self.assertEqual(res[key], subnet["subnet"][key])

    def test_create_subnet_two_default_routes_fails(self):
        routes = [dict(cidr="0.0.0.0/0", gateway="172.16.0.4"),
                  dict(cidr="0.0.0.0/0", gateway="172.16.0.4")]
        subnet = dict(
            subnet=dict(network_id=1,
                        tenant_id=self.context.tenant_id, ip_version=4,
                        cidr="172.16.0.0/24",
                        gateway_ip=neutron_attrs.ATTR_NOT_SPECIFIED,
                        dns_nameservers=neutron_attrs.ATTR_NOT_SPECIFIED,
                        host_routes=[
                            {"destination": "0.0.0.0/0",
                             "nexthop": "172.16.0.4"},
                            {"destination": "0.0.0.0/0",
                             "nexthop": "172.16.0.4"}],
                        allocation_pools=[{"start": "172.16.0.5",
                                           "end": "172.16.0.254"}],
                        enable_dhcp=None))
        with self._stubs(
            subnet=subnet["subnet"],
            routes=routes
        ) as (subnet_create, dns_create, route_create):
            dns_nameservers = subnet["subnet"].pop("dns_nameservers")
            gateway_ip = subnet["subnet"].pop("gateway_ip")
            subnet_request = copy.deepcopy(subnet)
            subnet_request["subnet"]["dns_nameservers"] = dns_nameservers
            subnet_request["subnet"]["gateway_ip"] = gateway_ip
            with self.assertRaises(q_exc.DuplicateRouteConflict):
                self.plugin.create_subnet(self.context, subnet_request)

    def test_create_subnet_default_route_gateway_ip(self):
        """Host_routes precedence

        If default route (host_routes) and gateway_ip are both provided,
        then host_route takes precedence.
        """

        routes = [dict(cidr="0.0.0.0/0", gateway="172.16.0.4")]
        subnet = dict(
            subnet=dict(network_id=1,
                        tenant_id=self.context.tenant_id, ip_version=4,
                        cidr="172.16.0.0/24",
                        gateway_ip="172.16.0.3",
                        dns_nameservers=neutron_attrs.ATTR_NOT_SPECIFIED,
                        host_routes=[{"destination": "0.0.0.0/0",
                                      "nexthop": "172.16.0.4"}],
                        allocation_pools=[{"start": "172.16.0.5",
                                           "end": "172.16.0.254"}],
                        enable_dhcp=None))
        with self._stubs(
            subnet=subnet["subnet"],
            routes=routes
        ) as (subnet_create, dns_create, route_create):
            dns_nameservers = subnet["subnet"].pop("dns_nameservers")
            subnet_request = copy.deepcopy(subnet)
            subnet_request["subnet"]["dns_nameservers"] = dns_nameservers
            res = self.plugin.create_subnet(self.context, subnet_request)
            self.assertEqual(subnet_create.call_count, 1)
            self.assertEqual(dns_create.call_count, 0)
            self.assertEqual(route_create.call_count, 1)
            self.assertEqual(res["gateway_ip"], "172.16.0.4")
            for key in subnet["subnet"].keys():
                if key == "gateway_ip":
                    self.assertEqual(res[key], "172.16.0.4")
                elif key == "host_routes":
                    self.assertEqual(len(res[key]), 0)
                else:
                    self.assertEqual(res[key], subnet["subnet"][key])

    def test_create_subnet_null_gateway_no_routes(self):
        """A subnet with a NULL gateway IP shouldn't create routes."""

        routes = [dict(cidr="0.0.0.0/0", gateway="172.16.0.4")]
        subnet = dict(
            subnet=dict(network_id=1,
                        tenant_id=self.context.tenant_id, ip_version=4,
                        cidr="172.16.0.0/24",
                        gateway_ip=None,
                        dns_nameservers=neutron_attrs.ATTR_NOT_SPECIFIED,
                        enable_dhcp=None))
        with self._stubs(
            subnet=subnet["subnet"],
            routes=routes
        ) as (subnet_create, dns_create, route_create):
            dns_nameservers = subnet["subnet"].pop("dns_nameservers")
            subnet_request = copy.deepcopy(subnet)
            subnet_request["subnet"]["dns_nameservers"] = dns_nameservers
            res = self.plugin.create_subnet(self.context, subnet_request)
            self.assertEqual(subnet_create.call_count, 1)
            self.assertEqual(dns_create.call_count, 0)
            self.assertEqual(route_create.call_count, 0)
            for key in subnet["subnet"].keys():
                if key == "gateway_ip":
                    self.assertIsNone(res[key])
                else:
                    self.assertEqual(res[key], subnet["subnet"][key])

    def test_create_subnet_routes_quota_pass(self):
        routes = (("0.0.0.0/0", "127.0.0.1"),
                  ("1.0.0.0/0", "127.0.0.1"),
                  ("2.0.0.0/0", "127.0.0.1"))
        host_routes = [{"destination": x, "nexthop": y} for x, y in routes]
        stub_routes = [{"cidr": x, "gateway": y} for x, y in routes]
        subnet = {"subnet":
                  {"cidr": "192.167.10.0/24", "created_at": datetime.now(),
                   "host_routes": host_routes, "id": 1, "ip_version": 4,
                   "network_id": 1, "tenant_id": self.context.tenant_id}}
        with self._stubs(subnet=subnet.get("subnet"), routes=stub_routes):
            self.plugin.create_subnet(self.context, subnet)

    def test_create_subnet_routes_quota_fail(self):
        routes = (("0.0.0.0/0", "127.0.0.1"),
                  ("1.0.0.0/0", "127.0.0.1"),
                  ("2.0.0.0/0", "127.0.0.1"),
                  ("3.0.0.0/0", "127.0.0.1"))
        host_routes = [{"destination": x, "nexthop": y} for x, y in routes]
        stub_routes = [{"cidr": x, "gateway": y} for x, y in routes]
        subnet = {"subnet":
                  {"cidr": "192.167.10.0/24", "created_at": datetime.now(),
                   "host_routes": host_routes, "id": 1, "ip_version": 4,
                   "network_id": 1, "tenant_id": self.context.tenant_id}}
        with self._stubs(subnet=subnet.get("subnet"), routes=stub_routes):
            with self.assertRaises(n_exc.OverQuota):
                self.plugin.create_subnet(self.context, subnet)

    def test_create_subnet_dns_quota_pass(self):
        nameservers = ["7.0.0.1", "7.0.0.2"]
        subnet = {"subnet":
                  {"cidr": "192.167.10.0/24", "created_at": datetime.now(),
                   "dns_nameservers": nameservers, "id": 1, "ip_version": 4,
                   "network_id": 1, "tenant_id": self.context.tenant_id}}
        with self._stubs(subnet=subnet.get("subnet"), dns=nameservers):
            self.plugin.create_subnet(self.context, subnet)

    def test_create_subnet_dns_quota_fail(self):
        nameservers = ["7.0.0.1", "7.0.0.2", "7.0.0.3"]
        subnet = {"subnet":
                  {"cidr": "192.167.10.0/24", "created_at": datetime.now(),
                   "dns_nameservers": nameservers, "id": 1, "ip_version": 4,
                   "network_id": 1, "tenant_id": self.context.tenant_id}}
        with self._stubs(subnet=subnet.get("subnet"), dns=nameservers):
            with self.assertRaises(n_exc.OverQuota):
                self.plugin.create_subnet(self.context, subnet)


class TestQuarkAllocationPoolCache(test_quark_plugin.TestQuarkPlugin):

    @contextlib.contextmanager
    def _stubs(self, has_subnet=True, host_routes=None, new_routes=None,
               find_routes=True, new_dns_servers=None, new_ip_policy=None,
               ip_version=4):
        if host_routes is None:
            host_routes = []
        if new_routes:
            new_routes = [models.Route(cidr=r["destination"],
                                       gateway=r["nexthop"],
                                       subnet_id=1)
                          for r in new_routes]
        if new_dns_servers:
            new_dns_servers = [models.DNSNameserver(
                ip=ip,
                subnet_id=1) for ip in new_dns_servers]
        if new_ip_policy:
            exc = [models.IPPolicyCIDR(cidr=excluded_cidr)
                   for excluded_cidr in new_ip_policy]
            new_ip_policy = models.IPPolicy(exclude=exc)

        if ip_version == 4:
            cidr = "172.16.0.0/24"
        else:
            cidr = "2607:f0d0:1002:51::0/64"

        subnet_mod = None
        if has_subnet:
            subnet = dict(
                id=0,
                network_id=1,
                tenant_id=self.context.tenant_id,
                ip_version=ip_version,
                cidr=cidr,
                host_routes=host_routes,
                dns_nameservers=["4.2.2.1", "4.2.2.2"],
                enable_dhcp=None,
                _allocation_pool_cache=None)

            dns_ips = subnet.pop("dns_nameservers", [])
            host_routes = subnet.pop("host_routes", [])
            exclude = [models.IPPolicyCIDR(cidr="172.16.0.0/32"),
                       models.IPPolicyCIDR(cidr="172.16.0.255/32")]
            subnet_mod = models.Subnet(
                ip_policy=models.IPPolicy(exclude=exclude),
                network=models.Network(id=1)
            )
            subnet_mod.update(subnet)

            subnet_mod["dns_nameservers"] = [models.DNSNameserver(ip=ip)
                                             for ip in dns_ips]
            subnet_mod["routes"] = [models.Route(cidr=r["destination"],
                                                 gateway=r["nexthop"],
                                                 subnet_id=subnet_mod["id"])
                                    for r in host_routes]
        with contextlib.nested(
            mock.patch("quark.db.api.subnet_find"),
            mock.patch("quark.db.api.subnet_update"),
            mock.patch("quark.db.api.dns_create"),
            mock.patch("quark.db.api.route_find"),
            mock.patch("quark.db.api.route_update"),
            mock.patch("quark.db.api.route_create"),
        ) as (subnet_find, subnet_update,
              dns_create, route_find, route_update, route_create):
            subnet_find.return_value = subnet_mod
            if has_subnet:
                route_find.return_value = (subnet_mod["routes"][0] if
                                           subnet_mod["routes"] and
                                           find_routes else None)
                new_subnet_mod = models.Subnet()
                new_subnet_mod.update(subnet_mod)
                new_subnet_mod.update(dict(id=1))
                if new_routes:
                    new_subnet_mod["routes"] = new_routes
                if new_dns_servers:
                    new_subnet_mod["dns_nameservers"] = new_dns_servers
                if new_ip_policy:
                    new_subnet_mod["ip_policy"] = new_ip_policy
                subnet_update.return_value = new_subnet_mod
            yield subnet_mod

    @mock.patch("quark.db.api.subnet_update_set_alloc_pool_cache")
    def test_update_subnet_allocation_pools_invalidate_cache(self, set_cache):
        og = cfg.CONF.QUARK.allow_allocation_pool_update
        cfg.CONF.set_override('allow_allocation_pool_update', True, 'QUARK')
        with self._stubs() as subnet_found:
            pools = [dict(start="172.16.0.1", end="172.16.0.12")]
            s = dict(subnet=dict(allocation_pools=pools))
            self.plugin.update_subnet(self.context, 1, s)
            self.assertEqual(set_cache.call_count, 1)
            set_cache.assert_called_with(self.context, subnet_found)
        cfg.CONF.set_override('allow_allocation_pool_update', og, 'QUARK')

    @mock.patch("quark.db.api.subnet_update_set_alloc_pool_cache")
    def test_get_subnet_set_alloc_cache_if_cache_is_none(self, set_cache):
        with self._stubs() as subnet_found:
            self.plugin.get_subnet(self.context, 1)
            self.assertEqual(set_cache.call_count, 1)
            set_cache.assert_called_with(self.context, subnet_found,
                                         [dict(start="172.16.0.1",
                                               end="172.16.0.254")])


class TestQuarkUpdateSubnet(test_quark_plugin.TestQuarkPlugin):
    DEFAULT_ROUTE = [dict(destination="0.0.0.0/0",
                          nexthop="172.16.0.1")]

    @contextlib.contextmanager
    def _stubs(self, has_subnet=True, host_routes=None, new_routes=None,
               find_routes=True, new_dns_servers=None, new_ip_policy=None,
               ip_version=4):
        if host_routes is None:
            host_routes = []
        if new_routes:
            new_routes = [models.Route(cidr=r["destination"],
                                       gateway=r["nexthop"],
                                       subnet_id=1)
                          for r in new_routes]
        if new_dns_servers:
            new_dns_servers = [models.DNSNameserver(
                ip=ip,
                subnet_id=1) for ip in new_dns_servers]
        if new_ip_policy:
            exc = [models.IPPolicyCIDR(cidr=excluded_cidr)
                   for excluded_cidr in new_ip_policy]
            new_ip_policy = models.IPPolicy(exclude=exc)

        if ip_version == 4:
            cidr = "172.16.0.0/24"
        else:
            cidr = "2607:f0d0:1002:51::0/64"

        subnet_mod = None
        if has_subnet:
            subnet = dict(
                id=0,
                network_id=1,
                tenant_id=self.context.tenant_id,
                ip_version=ip_version,
                cidr=cidr,
                host_routes=host_routes,
                dns_nameservers=["4.2.2.1", "4.2.2.2"],
                enable_dhcp=None)

            dns_ips = subnet.pop("dns_nameservers", [])
            host_routes = subnet.pop("host_routes", [])
            exclude = [models.IPPolicyCIDR(cidr="172.16.0.0/32"),
                       models.IPPolicyCIDR(cidr="172.16.0.255/32")]
            subnet_mod = models.Subnet(
                ip_policy=models.IPPolicy(exclude=exclude),
                network=models.Network(id=1)
            )
            subnet_mod.update(subnet)

            subnet_mod["dns_nameservers"] = [models.DNSNameserver(ip=ip)
                                             for ip in dns_ips]
            subnet_mod["routes"] = [models.Route(cidr=r["destination"],
                                                 gateway=r["nexthop"],
                                                 subnet_id=subnet_mod["id"])
                                    for r in host_routes]
        with contextlib.nested(
            mock.patch("quark.db.api.subnet_find"),
            mock.patch("quark.db.api.subnet_update"),
            mock.patch("quark.db.api.dns_create"),
            mock.patch("quark.db.api.route_find"),
            mock.patch("quark.db.api.route_update"),
            mock.patch("quark.db.api.route_create"),
        ) as (subnet_find, subnet_update,
              dns_create,
              route_find, route_update, route_create):
            subnet_find.return_value = subnet_mod
            if has_subnet:
                route_find.return_value = (subnet_mod["routes"][0] if
                                           subnet_mod["routes"] and
                                           find_routes else None)
                new_subnet_mod = models.Subnet()
                new_subnet_mod.update(subnet_mod)
                new_subnet_mod.update(dict(id=1))
                if new_routes:
                    new_subnet_mod["routes"] = new_routes
                if new_dns_servers:
                    new_subnet_mod["dns_nameservers"] = new_dns_servers
                if new_ip_policy:
                    new_subnet_mod["ip_policy"] = new_ip_policy
                subnet_update.return_value = new_subnet_mod
            yield dns_create, route_update, route_create

    def test_update_subnet_not_found(self):
        with self._stubs(has_subnet=False):
            with self.assertRaises(n_exc.SubnetNotFound):
                self.plugin.update_subnet(self.context, 1, {})

    def test_update_subnet_dns_nameservers(self):
        new_dns_servers = ["1.1.1.2"]
        with self._stubs(
            host_routes=self.DEFAULT_ROUTE,
            new_dns_servers=new_dns_servers
        ) as (dns_create, route_update, route_create):
            req = dict(subnet=dict(dns_nameservers=new_dns_servers))
            res = self.plugin.update_subnet(self.context,
                                            1,
                                            req)
            self.assertEqual(dns_create.call_count, 1)
            self.assertEqual(route_create.call_count, 0)
            self.assertEqual(res["dns_nameservers"], new_dns_servers)

    def test_update_subnet_routes(self):
        new_routes = [dict(destination="10.0.0.0/24",
                           nexthop="1.1.1.1")]
        with self._stubs(
            host_routes=self.DEFAULT_ROUTE,
            new_routes=new_routes
        ) as (dns_create, route_update, route_create):
            req = dict(subnet=dict(
                host_routes=new_routes))
            res = self.plugin.update_subnet(self.context, 1, req)
            self.assertEqual(dns_create.call_count, 0)
            self.assertEqual(route_create.call_count, 1)
            self.assertEqual(len(res["host_routes"]), 1)
            self.assertEqual(res["host_routes"][0]["destination"],
                             "10.0.0.0/24")
            self.assertEqual(res["host_routes"][0]["nexthop"],
                             "1.1.1.1")
            self.assertIsNone(res["gateway_ip"])

    def test_update_subnet_gateway_ip_with_default_route_in_db(self):
        with self._stubs(
            host_routes=self.DEFAULT_ROUTE,
            new_routes=[dict(destination="0.0.0.0/0", nexthop="1.2.3.4")]
        ) as (dns_create, route_update, route_create):
            req = dict(subnet=dict(gateway_ip="1.2.3.4"))
            res = self.plugin.update_subnet(self.context, 1, req)
            self.assertEqual(dns_create.call_count, 0)
            self.assertEqual(route_create.call_count, 0)
            self.assertEqual(route_update.call_count, 1)
            self.assertEqual(len(res["host_routes"]), 0)
            self.assertEqual(res["gateway_ip"], "1.2.3.4")

    def test_update_subnet_gateway_ip_with_non_default_route_in_db(self):
        with self._stubs(
            host_routes=[dict(destination="1.1.1.1/8", nexthop="9.9.9.9")],
            find_routes=False,
            new_routes=[dict(destination="1.1.1.1/8", nexthop="9.9.9.9"),
                        dict(destination="0.0.0.0/0", nexthop="1.2.3.4")]
        ) as (dns_create, route_update, route_create):
            req = dict(subnet=dict(gateway_ip="1.2.3.4"))
            res = self.plugin.update_subnet(self.context, 1, req)
            self.assertEqual(dns_create.call_count, 0)
            self.assertEqual(route_create.call_count, 1)

            self.assertEqual(res["gateway_ip"], "1.2.3.4")

            self.assertEqual(len(res["host_routes"]), 1)
            res_tuples = [(r["destination"], r["nexthop"])
                          for r in res["host_routes"]]
            self.assertIn(("1.1.1.1/8", "9.9.9.9"), res_tuples)

    def test_update_subnet_gateway_ip_without_default_route_in_db(self):
        with self._stubs(
            host_routes=None,
            new_routes=[dict(destination="0.0.0.0/0", nexthop="1.2.3.4")]
        ) as (dns_create, route_update, route_create):
            req = dict(subnet=dict(gateway_ip="1.2.3.4"))
            res = self.plugin.update_subnet(self.context, 1, req)
            self.assertEqual(dns_create.call_count, 0)
            self.assertEqual(route_create.call_count, 1)
            self.assertEqual(len(res["host_routes"]), 0)
            self.assertEqual(res["gateway_ip"], "1.2.3.4")

    def test_update_subnet_gateway_ip_with_default_route_in_args(self):
        new_routes = [dict(destination="0.0.0.0/0",
                           nexthop="4.3.2.1")]
        with self._stubs(
            host_routes=self.DEFAULT_ROUTE,
            new_routes=new_routes
        ) as (dns_create, route_update, route_create):
            req = dict(subnet=dict(
                host_routes=new_routes,
                gateway_ip="1.2.3.4"))
            res = self.plugin.update_subnet(self.context, 1, req)
            self.assertEqual(dns_create.call_count, 0)
            self.assertEqual(route_create.call_count, 1)
            self.assertEqual(len(res["host_routes"]), 0)
            self.assertEqual(res["gateway_ip"], "4.3.2.1")

    def test_update_subnet_allocation_pools_invalid_outside(self):
        og = cfg.CONF.QUARK.allow_allocation_pool_update
        cfg.CONF.set_override('allow_allocation_pool_update', True, 'QUARK')
        og1 = cfg.CONF.QUARK.allow_allocation_pool_growth
        cfg.CONF.set_override('allow_allocation_pool_growth', True, 'QUARK')
        pools = [dict(start="172.16.1.10", end="172.16.1.20")]
        s = dict(subnet=dict(allocation_pools=pools))
        try:
            with self._stubs() as (dns_create, route_update, route_create):
                with self.assertRaises(n_exc_ext.OutOfBoundsAllocationPool):
                    self.plugin.update_subnet(self.context, 1, s)
        finally:
            cfg.CONF.set_override('allow_allocation_pool_update', og, 'QUARK')
            cfg.CONF.set_override('allow_allocation_pool_growth', og1, 'QUARK')

    def test_update_subnet_allocation_pools_zero(self):
        with self._stubs() as (dns_create, route_update, route_create):
            resp = self.plugin.update_subnet(self.context, 1,
                                             dict(subnet=dict()))
            self.assertEqual(resp["allocation_pools"],
                             [dict(start="172.16.0.1", end="172.16.0.254")])

    def test_update_subnet_allocation_pools_one(self):
        og = cfg.CONF.QUARK.allow_allocation_pool_update
        cfg.CONF.set_override('allow_allocation_pool_update', True, 'QUARK')
        pools = [dict(start="172.16.0.10", end="172.16.0.20")]
        s = dict(subnet=dict(allocation_pools=pools))
        with self._stubs(
            new_ip_policy=[
                '172.16.0.0/29', '172.16.0.8/31', '172.16.0.21/32',
                '172.16.0.22/31', '172.16.0.24/29', '172.16.0.32/27',
                '172.16.0.64/26', '172.16.0.128/25']
        ) as (dns_create, route_update, route_create):
            resp = self.plugin.update_subnet(self.context, 1, s)
            self.assertEqual(resp["allocation_pools"], pools)
        cfg.CONF.set_override('allow_allocation_pool_update', og, 'QUARK')

    def test_update_subnet_allocation_pools_two(self):
        og = cfg.CONF.QUARK.allow_allocation_pool_update
        cfg.CONF.set_override('allow_allocation_pool_update', True, 'QUARK')
        pools = [dict(start="172.16.0.10", end="172.16.0.20"),
                 dict(start="172.16.0.40", end="172.16.0.50")]
        s = dict(subnet=dict(allocation_pools=pools))
        with self._stubs(
            new_ip_policy=[
                '172.16.0.0/29', '172.16.0.8/31', '172.16.0.21/32',
                '172.16.0.22/31', '172.16.0.24/29', '172.16.0.32/29',
                '172.16.0.51/32', '172.16.0.52/30', '172.16.0.56/29',
                '172.16.0.64/26', '172.16.0.128/25']
        ) as (dns_create, route_update, route_create):
            resp = self.plugin.update_subnet(self.context, 1, s)
            self.assertEqual(resp["allocation_pools"], pools)
        cfg.CONF.set_override('allow_allocation_pool_update', og, 'QUARK')

    def test_update_subnet_allocation_pools_three(self):
        og = cfg.CONF.QUARK.allow_allocation_pool_update
        cfg.CONF.set_override('allow_allocation_pool_update', True, 'QUARK')
        pools = [dict(start="172.16.0.5", end="172.16.0.254")]
        s = dict(subnet=dict(allocation_pools=pools))
        with self._stubs(
            new_ip_policy=['172.16.0.0/30', '172.16.0.4/32', '172.16.0.255/32']
        ) as (dns_create, route_update, route_create):
            resp = self.plugin.update_subnet(self.context, 1, s)
            self.assertEqual(resp["allocation_pools"], pools)
        cfg.CONF.set_override('allow_allocation_pool_update', og, 'QUARK')

    def test_update_subnet_allocation_pools_four(self):
        og = cfg.CONF.QUARK.allow_allocation_pool_update
        cfg.CONF.set_override('allow_allocation_pool_update', True, 'QUARK')
        pools = [dict(start="2607:f0d0:1002:51::a",
                      end="2607:f0d0:1002:51:ffff:ffff:ffff:fffe")]
        s = dict(subnet=dict(allocation_pools=pools))
        with self._stubs(
            ip_version=6,
            new_ip_policy=[
                '2607:f0d0:1002:51::/125', '2607:f0d0:1002:51::8/127',
                '2607:f0d0:1002:51:ffff:ffff:ffff:ffff/128']
        ) as (dns_create, route_update, route_create):
            resp = self.plugin.update_subnet(self.context, 1, s)
            self.assertEqual(resp["allocation_pools"], pools)
        cfg.CONF.set_override('allow_allocation_pool_update', og, 'QUARK')

    def test_update_subnet_allocation_pools_invalid(self):
        og = cfg.CONF.QUARK.allow_allocation_pool_update
        cfg.CONF.set_override('allow_allocation_pool_update', False, 'QUARK')
        pools = [dict(start="172.16.0.1", end="172.16.0.250")]
        s = dict(subnet=dict(allocation_pools=pools))
        with self._stubs() as (dns_create, route_update, route_create):
            with self.assertRaises(n_exc.BadRequest):
                self.plugin.update_subnet(self.context, 1, s)
        cfg.CONF.set_override('allow_allocation_pool_update', og, 'QUARK')

    def test_update_subnet_conflicting_gateway(self):
        og = cfg.CONF.QUARK.allow_allocation_pool_update
        cfg.CONF.set_override('allow_allocation_pool_update', True, 'QUARK')
        pools = [dict(start="172.16.0.1", end="172.16.0.254")]
        s = dict(subnet=dict(allocation_pools=pools, gateway_ip="172.16.0.1"))
        with self._stubs(
            new_ip_policy=['172.16.0.0/30', '172.16.0.4/32', '172.16.0.255/32']
        ) as (dns_create, route_update, route_create):
            with self.assertRaises(
                    n_exc_ext.GatewayConflictWithAllocationPools):
                self.plugin.update_subnet(self.context, 1, s)
        cfg.CONF.set_override('allow_allocation_pool_update', og, 'QUARK')


class TestQuarkDeleteSubnet(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, subnet, ips):
        ip_mods = []
        subnet_mod = None
        if subnet:
            subnet_mod = models.Subnet()
            subnet_mod.update(subnet)
        for ip in ips:
            ip_mod = models.IPAddress()
            ip_mod.update(ip)
            ip_mods.append(ip_mod)

        with contextlib.nested(
            mock.patch("quark.db.api.subnet_find"),
            mock.patch("quark.db.api.subnet_delete"),
            mock.patch("neutron.common.rpc.get_notifier")
        ) as (sub_find, sub_delete, get_notifier):
            if subnet_mod:
                subnet_mod.allocated_ips = ip_mods
            sub_find.return_value = subnet_mod
            yield sub_delete

    def test_delete_subnet(self):
        subnet = dict(id=1)
        with self._stubs(subnet=subnet, ips=[]) as sub_delete:
            self.plugin.delete_subnet(self.context, 1)
            self.assertTrue(sub_delete.called)

    def test_delete_subnet_no_subnet_fails(self):
        with self._stubs(subnet=None, ips=[]):
            with self.assertRaises(n_exc.SubnetNotFound):
                self.plugin.delete_subnet(self.context, 1)

    def test_delete_subnet_has_allocated_ips_fails(self):
        subnet = dict(id=1)
        with self._stubs(subnet=subnet, ips=[{}]):
            with self.assertRaises(n_exc.SubnetInUse):
                self.plugin.delete_subnet(self.context, 1)


class TestSubnetsQuotas(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, subnet_values, deleted_at=None):
        self.context.session.begin = mock.MagicMock()

        subnets = list()
        for s in subnet_values:
            s["network"] = models.Network()
            s["network"]["created_at"] = s["created_at"]
            s["dns_nameservers"] = []
            s["_allocation_pool_cache"] = None
            subnet = models.Subnet(**s)
            subnets.append(subnet)
        with contextlib.nested(
            mock.patch("quark.plugin_modules.subnets.get_subnets"),
            mock.patch("quark.db.api.subnet_find"),
            mock.patch("quark.db.api.network_find"),
            mock.patch("quark.db.api.subnet_create"),
            mock.patch("quark.db.api.subnet_delete"),
            mock.patch("neutron.common.rpc.get_notifier"),
            mock.patch("oslo_utils.timeutils.utcnow"),
            mock.patch("quark.plugin_modules.subnets._validate_subnet_cidr")
        ) as (get_subnets, sub_find, net_find, sub_create, sub_del, notify,
              time_func, sub_validate):
            sub_create.return_value = subnets[0]
            sub_find.return_value = subnets[0]
            retsubs = []
            if len(subnets) > 1:
                retsubs = subnets[1:]
            get_subnets.return_value = retsubs
            time_func.return_value = deleted_at
            yield notify

    def test_create_subnet_v4_alongside_v6_quota_pass(self):
        original_4 = cfg.CONF.QUOTAS.quota_v4_subnets_per_network
        original_6 = cfg.CONF.QUOTAS.quota_v6_subnets_per_network
        s = [dict(network_id=1, cidr="192.167.10.0/24",
                  tenant_id=1, id=1, created_at="123"),
             dict(network_id=1, cidr="::0/24",
                  tenant_id=1, id=2, created_at="123")]
        with self._stubs(s):
            cfg.CONF.set_override('quota_v4_subnets_per_network', 1, "QUOTAS")
            cfg.CONF.set_override('quota_v6_subnets_per_network', 1, "QUOTAS")
            self.plugin.create_subnet(self.context, dict(subnet=s[0]))
            cfg.CONF.set_override('quota_v4_subnets_per_network', original_4,
                                  "QUOTAS")
            cfg.CONF.set_override('quota_v6_subnets_per_network', original_6,
                                  "QUOTAS")

    def test_create_subnet_v4_quota_pass(self):
        original_4 = cfg.CONF.QUOTAS.quota_v4_subnets_per_network
        s = [dict(network_id=1, cidr="192.167.10.0/24",
                  tenant_id=1, id=1, created_at="123")]
        with self._stubs(s):
            cfg.CONF.set_override('quota_v4_subnets_per_network', 1, "QUOTAS")
            self.plugin.create_subnet(self.context, dict(subnet=s[0]))
            cfg.CONF.set_override('quota_v4_subnets_per_network', original_4,
                                  "QUOTAS")

    def test_create_subnet_v6_quota_pass(self):
        original_6 = cfg.CONF.QUOTAS.quota_v6_subnets_per_network
        s = [dict(network_id=1, cidr="::0/24",
                  tenant_id=1, id=1, created_at="123")]
        with self._stubs(s):
            cfg.CONF.set_override('quota_v6_subnets_per_network', 1, "QUOTAS")
            self.plugin.create_subnet(self.context, dict(subnet=s[0]))
            cfg.CONF.set_override('quota_v6_subnets_per_network', original_6,
                                  "QUOTAS")

    def test_create_subnet_v4_quota_fail(self):
        original_4 = cfg.CONF.QUOTAS.quota_v4_subnets_per_network
        s = [dict(network_id=1, cidr="192.167.10.0/24",
                  tenant_id=1, id=1, created_at="123"),
             dict(network_id=1, cidr="192.168.10.0/24",
                  tenant_id=1, id=2, created_at="124")]
        with self._stubs(s):
            cfg.CONF.set_override('quota_v4_subnets_per_network', 1, "QUOTAS")
            with self.assertRaises(n_exc.OverQuota):
                self.plugin.create_subnet(self.context, dict(subnet=s[0]))
            cfg.CONF.set_override('quota_v4_subnets_per_network', original_4,
                                  "QUOTAS")

    def test_create_subnet_v6_quota_fail(self):
        original_6 = cfg.CONF.QUOTAS.quota_v6_subnets_per_network
        s = [dict(network_id=1, cidr="::0/24",
                  tenant_id=1, id=1, created_at="123"),
             dict(network_id=1, cidr="::1/24",
                  tenant_id=1, id=2, created_at="124")]
        with self._stubs(s):
            cfg.CONF.set_override('quota_v6_subnets_per_network', 1, "QUOTAS")
            with self.assertRaises(n_exc.OverQuota):
                self.plugin.create_subnet(self.context, dict(subnet=s[0]))
            cfg.CONF.set_override('quota_v6_subnets_per_network', original_6,
                                  "QUOTAS")

    def test_create_subnet_zero_quota_fail(self):
        original_4 = cfg.CONF.QUOTAS.quota_v4_subnets_per_network
        s = [dict(network_id=1, cidr="192.167.10.0/24",
                  tenant_id=1, id=1, created_at="123")]
        with self._stubs(s):
            cfg.CONF.set_override('quota_v4_subnets_per_network', 0, "QUOTAS")
            with self.assertRaises(n_exc.OverQuota):
                self.plugin.create_subnet(self.context, dict(subnet=s[0]))
            cfg.CONF.set_override('quota_v4_subnets_per_network', original_4,
                                  "QUOTAS")

    def test_create_subnet_negative_one_quota_pass(self):
        original_4 = cfg.CONF.QUOTAS.quota_v4_subnets_per_network
        s = [dict(network_id=1, cidr="192.167.10.0/24",
                  tenant_id=1, id=1, created_at="123")]
        with self._stubs(s):
            cfg.CONF.set_override('quota_v4_subnets_per_network', 0, "QUOTAS")
            with self.assertRaises(n_exc.OverQuota):
                self.plugin.create_subnet(self.context, dict(subnet=s[0]))
            cfg.CONF.set_override('quota_v4_subnets_per_network', -1, "QUOTAS")
            self.plugin.create_subnet(self.context, dict(subnet=s[0]))
            cfg.CONF.set_override('quota_v4_subnets_per_network', original_4,
                                  "QUOTAS")


class TestSubnetsNotification(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, s, deleted_at=None):
        class FakeContext(object):
            def __enter__(*args, **kwargs):
                pass

            def __exit__(*args, **kwargs):
                pass

        self.context.session.begin = FakeContext

        s["network"] = models.Network()
        s["network"]["created_at"] = s["created_at"]
        subnet = models.Subnet(**s)
        with contextlib.nested(
            mock.patch("quark.plugin_modules.subnets.get_subnets"),
            mock.patch("quark.db.api.subnet_find"),
            mock.patch("quark.db.api.network_find"),
            mock.patch("quark.db.api.subnet_create"),
            mock.patch("quark.db.api.subnet_delete"),
            mock.patch("neutron.common.rpc.get_notifier"),
            mock.patch("neutron.quota.QUOTAS"),
            mock.patch("oslo_utils.timeutils.utcnow"),
            mock.patch("quark.plugin_modules.subnets._validate_subnet_cidr")
        ) as (get_subnets, sub_find, net_find, sub_create, sub_del, notify,
              quota_engine, time_func, sub_validate):
            sub_create.return_value = subnet
            get_subnets.return_value = []
            sub_find.return_value = subnet
            time_func.return_value = deleted_at
            yield notify

    def test_create_subnet_notification(self):
        s = dict(network_id=1, cidr="192.168.10.0/24",
                 tenant_id=1, id=1, created_at="123")
        with self._stubs(s) as notify:
            admin_ctx = self.context.elevated()
            self.plugin.create_subnet(admin_ctx, dict(subnet=s))
            notify.assert_called_once_with("network")
            notify.return_value.info.assert_called_once_with(
                admin_ctx,
                "ip_block.create",
                dict(tenant_id=s["tenant_id"],
                     ip_block_id=s["id"],
                     created_at=s["created_at"]))

    def test_delete_subnet_notification(self):
        now = time.strftime('%Y-%m-%d %H:%M:%S')
        later = time.strftime('%Y-%m-%d %H:%M:%S')
        s = dict(tenant_id=1, id=1, created_at=now)
        with self._stubs(s, deleted_at=later) as notify:
            self.plugin.delete_subnet(self.context, 1)
            notify.assert_called_once_with("network")
            notify.return_value.info.assert_called_once_with(
                self.context,
                "ip_block.delete",
                dict(tenant_id=s["tenant_id"],
                     created_at=s["created_at"],
                     ip_block_id=s["id"],
                     deleted_at=later))


class TestQuarkDiagnoseSubnets(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, subnets=None, routes=None):
        if routes is None:
            routes = []
        route_models = []
        for route in routes:
            r = models.Route()
            r.update(route)
            route_models.append(r)

        if isinstance(subnets, list):
            subnet_models = []
            for subnet in subnets:
                s_dict = subnet.copy()
                s_dict["routes"] = route_models
                s = models.Subnet(network=models.Network())
                s.update(s_dict)
                subnet_models.append(s)
        elif subnets:
            mod = models.Subnet(network=models.Network())
            mod.update(subnets)
            mod["routes"] = route_models
            subnet_models = mod
        else:
            subnet_models = None

        with mock.patch("quark.db.api.subnet_find") as subnet_find:
            subnet_find.return_value = subnet_models
            yield

    def test_diagnose_subnet_with_wildcard_id_no_existing_subnets(self):
        with self._stubs(subnets=[], routes=[]):
            expected = {'subnets': []}
            actual = self.plugin.diagnose_subnet(self.context.elevated(), "*",
                                                 None)
            self.assertEqual(expected, actual)

    def test_diagnose_subnet_not_authorized(self):
        with self._stubs(subnets=[], routes=[]):
            with self.assertRaises(n_exc.NotAuthorized):
                self.plugin.diagnose_subnet(self.context, "*", None)

    def test_diagnose_subnet_with_wildcard_with_existing_subnets(self):
        subnet_id = str(uuid.uuid4())
        route = dict(id=1, cidr="0.0.0.0/0", gateway="192.168.0.1")

        subnet = dict(id=subnet_id, network_id=1, name=subnet_id,
                      tenant_id=self.context.tenant_id, ip_version=4,
                      cidr="192.168.0.0/24", gateway_ip="192.168.0.1",
                      dns_nameservers=[],
                      enable_dhcp=None)

        with self._stubs(subnets=[subnet], routes=[route]):
            actual = self.plugin.diagnose_subnet(self.context.elevated(), "*",
                                                 None)
            self.maxDiff = None
            self.assertEqual(subnet["id"], actual["subnets"][0]["id"])

    def test_diagnose_subnet_with_regular_id(self):
        subnet_id = "12345"
        route = dict(id=1, cidr="0.0.0.0/0", gateway="192.168.0.1")

        subnet = dict(id=subnet_id, network_id=1, name=subnet_id,
                      tenant_id=self.context.tenant_id, ip_version=4,
                      cidr="192.168.0.0/24", gateway_ip="192.168.0.1",
                      dns_nameservers=[],
                      enable_dhcp=None)

        with self._stubs(subnets=subnet, routes=[route]):
            actual = self.plugin.diagnose_subnet(self.context.elevated(),
                                                 subnet_id, None)
            self.assertEqual(subnet["id"], actual["subnets"]["id"])


class TestQuarkCreateSubnetAttrFilters(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self):
        with contextlib.nested(
            mock.patch("quark.db.api.subnet_create"),
            mock.patch("quark.db.api.network_find"),
            mock.patch("quark.db.api.dns_create"),
            mock.patch("quark.db.api.route_create"),
            mock.patch("quark.plugin_views._make_subnet_dict"),
            mock.patch("quark.db.api.subnet_find"),
            mock.patch("neutron.common.rpc.get_notifier")
        ) as (subnet_create, net_find, dns_create, route_create, sub_dict,
              subnet_find, get_notifier):
            route_create.return_value = models.Route()
            yield subnet_create, net_find

    def test_create_subnet(self):
        subnet = {"subnet": {
            "network_id": 1, "tenant_id": self.context.tenant_id,
            "ip_version": 4, "cidr": "172.16.0.0/24",
            "gateway_ip": "0.0.0.0",
            "dns_nameservers": neutron_attrs.ATTR_NOT_SPECIFIED,
            "host_routes": neutron_attrs.ATTR_NOT_SPECIFIED,
            "enable_dhcp": None, "first_ip": 0, "last_ip": 1,
            "next_auto_assign_ip": 10}}

        with self._stubs() as (subnet_create, net_find):
            subnet_create.return_value = models.Subnet(
                cidr=subnet["subnet"]["cidr"])
            self.plugin.create_subnet(self.context, subnet)
            self.assertEqual(subnet_create.call_count, 1)
            subnet_create.assert_called_once_with(
                self.context, network_id=subnet["subnet"]["network_id"],
                tenant_id=subnet["subnet"]["tenant_id"],
                cidr=subnet["subnet"]["cidr"], network=net_find())

    def test_create_subnet_admin(self):
        subnet = {"subnet": {
            "network_id": 1, "tenant_id": self.context.tenant_id,
            "ip_version": 4, "cidr": "172.16.0.0/24",
            "gateway_ip": "0.0.0.0",
            "dns_nameservers": neutron_attrs.ATTR_NOT_SPECIFIED,
            "host_routes": neutron_attrs.ATTR_NOT_SPECIFIED,
            "enable_dhcp": None, "first_ip": 0, "last_ip": 1,
            "next_auto_assign_ip": 10}}

        admin_ctx = self.context.elevated()
        with self._stubs() as (subnet_create, net_find):
            subnet_create.return_value = models.Subnet(
                cidr=subnet["subnet"]["cidr"])
            self.plugin.create_subnet(admin_ctx, subnet)
            self.assertEqual(subnet_create.call_count, 1)
            subnet_create.assert_called_once_with(
                admin_ctx, network_id=subnet["subnet"]["network_id"],
                tenant_id=subnet["subnet"]["tenant_id"],
                cidr=subnet["subnet"]["cidr"], network=net_find(),
                next_auto_assign_ip=subnet["subnet"]["next_auto_assign_ip"])


class TestQuarkUpdateSubnetAttrFilters(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self):
        pool_mod = "quark.allocation_pool.AllocationPools"
        with contextlib.nested(
            mock.patch("quark.db.api.subnet_find"),
            mock.patch("quark.db.api.subnet_update"),
            mock.patch("quark.db.api.dns_create"),
            mock.patch("quark.db.api.route_find"),
            mock.patch("quark.db.api.route_update"),
            mock.patch("quark.db.api.route_create"),
            mock.patch(pool_mod),
            mock.patch("quark.plugin_views._make_subnet_dict")
        ) as (subnet_find, subnet_update, dns_create, route_find,
              route_update, route_create, make_subnet, gateway_exclude):
            yield subnet_update, subnet_find

    def test_update_subnet_attr_filters(self):
        subnet = {"subnet": {
            "network_id": 1, "tenant_id": self.context.tenant_id,
            "ip_version": 4, "cidr": "172.16.0.0/24",
            "gateway_ip": "0.0.0.0",
            "dns_nameservers": neutron_attrs.ATTR_NOT_SPECIFIED,
            "host_routes": neutron_attrs.ATTR_NOT_SPECIFIED,
            "enable_dhcp": None, "first_ip": 0, "last_ip": 1,
            "next_auto_assign_ip": 10, "do_not_use": False}}

        with self._stubs() as (subnet_update, subnet_find):
            self.plugin.update_subnet(self.context, 1, subnet)

            # NOTE(mdietz): the assertion here shows that, without admin,
            #               all of the attributes passed above are stripped
            #               from the request body. Otherwise, the attributes
            #               above would be passed as keyword arguments to the
            #               subnet_update db api call.
            subnet_update.assert_called_once_with(
                self.context, subnet_find())

    def test_update_subnet_attr_filters_admin(self):
        subnet = {"subnet": {
            "network_id": 1, "tenant_id": self.context.tenant_id,
            "ip_version": 4, "cidr": "172.16.0.0/24",
            "gateway_ip": "0.0.0.0",
            "dns_nameservers": neutron_attrs.ATTR_NOT_SPECIFIED,
            "host_routes": neutron_attrs.ATTR_NOT_SPECIFIED,
            "enable_dhcp": False, "first_ip": 0, "last_ip": 1,
            "next_auto_assign_ip": 10, "do_not_use": True}}

        admin_ctx = self.context.elevated()
        with self._stubs() as (subnet_update, subnet_find):
            self.plugin.update_subnet(admin_ctx, 1, subnet)
            subnet_update.assert_called_once_with(
                admin_ctx, subnet_find(),
                next_auto_assign_ip=subnet["subnet"]["next_auto_assign_ip"],
                tenant_id=subnet["subnet"]["tenant_id"],
                enable_dhcp=subnet["subnet"]["enable_dhcp"],
                do_not_use=subnet["subnet"]["do_not_use"])


class TestQuarkGetSubnetsShared(test_quark_plugin.TestQuarkPlugin):
    def setUp(self):
        super(TestQuarkGetSubnetsShared, self).setUp()
        self.strategy = {"public_network":
                         {"bridge": "xenbr0",
                          "subnets": {"4": "public_v4",
                                      "6": "public_v6"}}}
        self.strategy_json = json.dumps(self.strategy)
        self.old = plugin_views.STRATEGY
        plugin_views.STRATEGY = network_strategy.JSONStrategy(
            self.strategy_json)
        cfg.CONF.set_override("default_net_strategy", self.strategy_json,
                              "QUARK")

    def tearDown(self):
        plugin_views.STRATEGY = self.old

    @contextlib.contextmanager
    def _stubs(self, subnets=None):
        subnet_mods = []

        if isinstance(subnets, list):
            for sub in subnets:
                subnet_mod = models.Subnet()
                subnet_mod.update(sub)
                subnet_mods.append(subnet_mod)

        db_mod = "quark.db.api"
        db_api.STRATEGY = network_strategy.JSONStrategy(self.strategy_json)
        network_strategy.STRATEGY = network_strategy.JSONStrategy(
            self.strategy_json)

        with mock.patch("%s._subnet_find" % db_mod) as subnet_find:
            subnet_find.return_value = subnet_mods
            yield subnet_find

    def test_get_subnets_shared(self):
        sub0 = dict(id='public_v4', tenant_id="provider", name="public_v4",
                    _cidr="0.0.0.0/0", network_id="public_network")
        sub1 = dict(id='public_v6', tenant_id="provider", name="public_v6",
                    _cidr="::/0", network_id="public_network")

        with self._stubs(subnets=[sub0, sub1]) as subnet_find:
            ret = self.plugin.get_subnets(self.context, None, None, None,
                                          False, {"shared": [True]})
            for sub in ret:
                self.assertEqual("public_network", sub["network_id"])

            subnet_find.assert_called_with(self.context, None, None, False,
                                           None, None,
                                           join_routes=True,
                                           defaults=["public_v4", "public_v6"],
                                           join_dns=True,
                                           join_pool=True,
                                           provider_query=False)

    def test_get_subnets_shared_false(self):
        sub0 = dict(id='public_v4', tenant_id="provider", name="public_v4",
                    _cidr="0.0.0.0/0", network_id="public_network")
        sub1 = dict(id='public_v6', tenant_id="provider", name="public_v6",
                    _cidr="::/0", network_id="public_network")

        with self._stubs(subnets=[sub0, sub1]) as subnet_find:
            self.plugin.get_subnets(self.context, None, None, None,
                                    False, {"shared": [False]})
            invert = db_api.INVERT_DEFAULTS
            subnet_find.assert_called_with(self.context, None, None, False,
                                           None, None,
                                           defaults=[invert, "public_v4",
                                                     "public_v6"],
                                           provider_query=False,
                                           join_routes=True, join_dns=True,
                                           join_pool=True)

    def test_get_subnets_no_shared(self):
        sub0 = dict(id='public_v4', tenant_id="provider", name="public_v4",
                    _cidr="0.0.0.0/0", network_id="public_network")
        sub1 = dict(id='tenant_v4', tenant_id="tenant", name="tenant_v4",
                    _cidr="0.0.0.0/0", network_id="tenant_network")

        with self._stubs(subnets=[sub0, sub1]) as subnet_find:
            self.plugin.get_subnets(self.context, None, None, None,
                                    False)
            subnet_find.assert_called_with(self.context, None, None, False,
                                           None, None,
                                           defaults=[],
                                           provider_query=False,
                                           join_routes=True, join_dns=True,
                                           join_pool=True)
