# Copyright 2013 Openstack Foundation
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
import time
import uuid

import mock
from neutron.api.v2 import attributes as neutron_attrs
from neutron.common import exceptions
from neutron.openstack.common.notifier import api as notifier_api
from oslo.config import cfg

from quark.db import models
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
        expected_route = dict(destination=route["cidr"],
                              nexthop=route["gateway"])

        with self._stubs(subnets=[subnet], routes=[route]):
            res = self.plugin.get_subnets(self.context, {}, {})
            # Compare routes separately
            routes = res[0].pop("host_routes")
            for key in subnet.keys():
                self.assertEqual(res[0][key], subnet[key])
            for key in expected_route.keys():
                self.assertEqual(routes[0][key], expected_route[key])

    def test_subnet_show_fail(self):
        with self._stubs():
            with self.assertRaises(exceptions.SubnetNotFound):
                self.plugin.get_subnet(self.context, 1)

    def test_subnet_show(self):
        subnet_id = str(uuid.uuid4())
        route = dict(id=1, cidr="0.0.0.0/0", gateway="192.168.0.1",
                     subnet_id=subnet_id)

        expected_route = dict(destination=route["cidr"],
                              nexthop=route["gateway"])

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
            for key in expected_route.keys():
                self.assertEqual(routes[0][key], expected_route[key])


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
            res = self.plugin.get_subnets(self.context, {}, {})
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
            mock.patch("quark.db.api.subnet_create")
        ) as (net_find, subnet_find, subnet_create):
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
            with self.assertRaises(exceptions.InvalidInput):
                s = dict(subnet=dict(cidr="192.168.1.1/8",
                                     network_id=1))
                self.plugin.create_subnet(self.context, s)


class TestQuarkCreateSubnetAllocationPools(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, subnet):
        s = models.Subnet(network=models.Network(id=1, subnets=[]))
        s.update(subnet)

        with contextlib.nested(
            mock.patch("quark.db.api.network_find"),
            mock.patch("quark.db.api.subnet_find"),
            mock.patch("quark.db.api.subnet_create"),
        ) as (net_find, subnet_find, subnet_create):
            net_find.return_value = s["network"]
            subnet_find.return_value = []
            subnet_create.return_value = s
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
            cidr="2607:f0d0:1002:51::0/96",
            network_id=1))
        with self._stubs(s["subnet"]) as (subnet_create):
            resp = self.plugin.create_subnet(self.context, s)
            self.assertEqual(subnet_create.call_count, 1)
            self.assertEqual(resp["allocation_pools"], pools)

    def test_create_subnet_allocation_pools_empty_list(self):
        pools = []
        s = dict(subnet=dict(
            allocation_pools=pools,
            cidr="192.168.1.1/24",
            network_id=1))
        with self._stubs(s["subnet"]) as (subnet_create):
            resp = self.plugin.create_subnet(self.context, s)
            self.assertEqual(subnet_create.call_count, 1)
            expected_pools = [{'start': '192.168.1.1',
                              'end': '192.168.1.254'}]
            self.assertEqual(resp["allocation_pools"], expected_pools)


# TODO(amir): Refactor the tests to test individual subnet attributes.
# * copy.deepcopy was necessary to maintain tests on keys, which is a bit ugly.
# * workaround is also in place for lame ATTR_NOT_SPECIFIED object()
class TestQuarkCreateSubnet(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, subnet=None, network=None, routes=None, dns=None):

        if network:
            net = models.Network()
            net.update(network)
            network = net
        subnet_mod = models.Subnet(network=models.Network())
        dns_ips = subnet.pop("dns_nameservers", [])
        host_routes = subnet.pop("host_routes", [])
        subnet_mod.update(subnet)

        subnet["dns_nameservers"] = dns_ips
        subnet["host_routes"] = host_routes
        routes = routes or []
        dns = dns or []
        route_models = [models.Route(**r) for r in routes]
        dns_models = [models.DNSNameserver(**d) for d in dns]

        with contextlib.nested(
            mock.patch("quark.db.api.subnet_create"),
            mock.patch("quark.db.api.network_find"),
            mock.patch("quark.db.api.dns_create"),
            mock.patch("quark.db.api.route_create"),
        ) as (subnet_create, net_find, dns_create, route_create):
            subnet_create.return_value = subnet_mod
            net_find.return_value = network
            route_create.side_effect = route_models
            dns_create.side_effect = dns_models
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
        network = dict(network_id=1)
        with self._stubs(
            subnet=subnet["subnet"],
            network=network,
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

    def test_create_subnet_not_admin_segment_id_ignored(self):
        routes = [dict(cidr="0.0.0.0/0", gateway="0.0.0.0")]
        subnet = dict(
            subnet=dict(network_id=1,
                        tenant_id=self.context.tenant_id, ip_version=4,
                        cidr="172.16.0.0/24", gateway_ip="0.0.0.0",
                        dns_nameservers=neutron_attrs.ATTR_NOT_SPECIFIED,
                        host_routes=neutron_attrs.ATTR_NOT_SPECIFIED,
                        enable_dhcp=None))
        network = dict(network_id=1)
        with self._stubs(
            subnet=subnet["subnet"],
            network=network,
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
        with self._stubs(subnet=dict(), network=None):
            with self.assertRaises(exceptions.NetworkNotFound):
                self.plugin.create_subnet(self.context, subnet)

    def test_create_subnet_no_gateway_ip_defaults(self):
        routes = [dict(cidr="0.0.0.0/0", gateway="172.16.0.1")]
        subnet = dict(
            subnet=dict(network_id=1,
                        tenant_id=self.context.tenant_id, ip_version=4,
                        cidr="172.16.0.0/24",
                        gateway_ip=neutron_attrs.ATTR_NOT_SPECIFIED,
                        dns_nameservers=neutron_attrs.ATTR_NOT_SPECIFIED,
                        enable_dhcp=None))
        network = dict(network_id=1)
        with self._stubs(
            subnet=subnet["subnet"],
            network=network,
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
                    self.assertEqual(res[key], "172.16.0.1")
                elif key == "host_routes":
                    self.assertEqual(res[key][0]["destination"], "0.0.0.0/0")
                    self.assertEqual(res[key][0]["nexthop"], "172.16.0.1")
                else:
                    self.assertEqual(res[key], subnet["subnet"][key])

    def test_create_subnet_dns_nameservers(self):
        routes = [dict(cidr="0.0.0.0/0", gateway="0.0.0.0")]
        dns_ns = [dict(ip="4.2.2.1"), dict(ip="4.2.2.2")]
        subnet = dict(
            subnet=dict(network_id=1,
                        tenant_id=self.context.tenant_id, ip_version=4,
                        cidr="172.16.0.0/24", gateway_ip="0.0.0.0",
                        dns_nameservers=["4.2.2.1", "4.2.2.2"],
                        enable_dhcp=None))
        network = dict(network_id=1)
        with self._stubs(
            subnet=subnet["subnet"],
            network=network,
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
                    self.assertEqual(res[key][0]["destination"], "0.0.0.0/0")
                    self.assertEqual(res[key][0]["nexthop"], "0.0.0.0")
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
                        enable_dhcp=None))
        network = dict(network_id=1)
        with self._stubs(
            subnet=subnet["subnet"],
            network=network,
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
                    self.assertIn(("0.0.0.0/0", "0.0.0.0"), res_tuples)
                    self.assertEqual(2, len(res_tuples))
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
                        enable_dhcp=None))
        network = dict(network_id=1)
        with self._stubs(
            subnet=subnet["subnet"],
            network=network,
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
                if key == "host_routes":
                    res_tuples = [(r["destination"], r["nexthop"])
                                  for r in res[key]]
                    self.assertEqual([("0.0.0.0/0", "172.16.0.4")], res_tuples)
                elif key == "gateway_ip":
                    self.assertEqual(res[key], "172.16.0.4")
                else:
                    self.assertEqual(res[key], subnet["subnet"][key])

    def test_create_subnet_default_route_gateway_ip(self):
        """If default route (host_routes) and gateway_ip are both provided,
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
                        enable_dhcp=None))
        network = dict(network_id=1)
        with self._stubs(
            subnet=subnet["subnet"],
            network=network,
            routes=routes
        ) as (subnet_create, dns_create, route_create):
            dns_nameservers = subnet["subnet"].pop("dns_nameservers")
            subnet_request = copy.deepcopy(subnet)
            subnet_request["subnet"]["dns_nameservers"] = dns_nameservers
            res = self.plugin.create_subnet(self.context, subnet_request)
            self.assertEqual(subnet_create.call_count, 1)
            self.assertEqual(dns_create.call_count, 0)
            self.assertEqual(route_create.call_count, 1)
            for key in subnet["subnet"].keys():
                if key == "host_routes":
                    res_tuples = [(r["destination"], r["nexthop"])
                                  for r in res[key]]
                    self.assertEqual([("0.0.0.0/0", "172.16.0.4")], res_tuples)
                elif key == "gateway_ip":
                    self.assertEqual(res[key], "172.16.0.4")
                else:
                    self.assertEqual(res[key], subnet["subnet"][key])

    def test_create_subnet_null_gateway_no_routes(self):
        """Creating a subnet with a NULL gateway IP shouldn't
        create routes.
        """
        routes = [dict(cidr="0.0.0.0/0", gateway="172.16.0.4")]
        subnet = dict(
            subnet=dict(network_id=1,
                        tenant_id=self.context.tenant_id, ip_version=4,
                        cidr="172.16.0.0/24",
                        gateway_ip=None,
                        dns_nameservers=neutron_attrs.ATTR_NOT_SPECIFIED,
                        enable_dhcp=None))
        network = dict(network_id=1)
        with self._stubs(
            subnet=subnet["subnet"],
            network=network,
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


class TestQuarkUpdateSubnet(test_quark_plugin.TestQuarkPlugin):
    DEFAULT_ROUTE = [dict(destination="0.0.0.0/0",
                          nexthop="172.16.0.1")]

    @contextlib.contextmanager
    def _stubs(self, host_routes=None, new_routes=None, find_routes=True,
               new_dns_servers=None):
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

        subnet = dict(
            id=1,
            network_id=1,
            tenant_id=self.context.tenant_id, ip_version=4,
            cidr="172.16.0.0/24",
            host_routes=host_routes,
            dns_nameservers=["4.2.2.1", "4.2.2.2"],
            enable_dhcp=None)

        dns_ips = subnet.pop("dns_nameservers", [])
        host_routes = subnet.pop("host_routes", [])
        subnet_mod = models.Subnet()

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
            route_find.return_value = subnet_mod["routes"][0] \
                if subnet_mod["routes"] and find_routes else None
            new_subnet_mod = models.Subnet(network=models.Network())
            new_subnet_mod.update(subnet_mod)
            if new_routes:
                new_subnet_mod["routes"] = new_routes
            if new_dns_servers:
                new_subnet_mod["dns_nameservers"] = new_dns_servers
            subnet_update.return_value = new_subnet_mod
            yield dns_create, route_update, route_create

    def test_update_subnet_not_found(self):
        with self.assertRaises(exceptions.SubnetNotFound):
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
            self.assertEqual(len(res["host_routes"]), 1)
            self.assertEqual(res["host_routes"][0]["destination"],
                             "0.0.0.0/0")
            self.assertEqual(res["host_routes"][0]["nexthop"],
                             "1.2.3.4")
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

            self.assertEqual(len(res["host_routes"]), 2)
            res_tuples = [(r["destination"], r["nexthop"])
                          for r in res["host_routes"]]
            self.assertIn(("0.0.0.0/0", "1.2.3.4"), res_tuples)
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
            self.assertEqual(len(res["host_routes"]), 1)
            self.assertEqual(res["host_routes"][0]["destination"],
                             "0.0.0.0/0")
            self.assertEqual(res["host_routes"][0]["nexthop"],
                             "1.2.3.4")
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
            self.assertEqual(len(res["host_routes"]), 1)
            self.assertEqual(res["host_routes"][0]["destination"],
                             "0.0.0.0/0")
            self.assertEqual(res["host_routes"][0]["nexthop"],
                             "4.3.2.1")
            self.assertEqual(res["gateway_ip"], "4.3.2.1")


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

        db_mod = "quark.db.api"
        with contextlib.nested(
            mock.patch("%s.subnet_find" % db_mod),
            mock.patch("%s.subnet_delete" % db_mod)
        ) as (sub_find, sub_delete):
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
            with self.assertRaises(exceptions.SubnetNotFound):
                self.plugin.delete_subnet(self.context, 1)

    def test_delete_subnet_has_allocated_ips_fails(self):
        subnet = dict(id=1)
        with self._stubs(subnet=subnet, ips=[{}]):
            with self.assertRaises(exceptions.SubnetInUse):
                self.plugin.delete_subnet(self.context, 1)


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
        db_mod = "quark.db.api"
        api_mod = "neutron.openstack.common.notifier.api"
        time_mod = "neutron.openstack.common.timeutils"
        sub_plugin_mod = "quark.plugin_modules.subnets"
        with contextlib.nested(
            mock.patch("%s.subnet_find" % db_mod),
            mock.patch("%s.network_find" % db_mod),
            mock.patch("%s.subnet_create" % db_mod),
            mock.patch("%s.subnet_delete" % db_mod),
            mock.patch("%s.notify" % api_mod),
            mock.patch("%s.utcnow" % time_mod),
            mock.patch("%s._validate_subnet_cidr" % sub_plugin_mod)
        ) as (sub_find, net_find, sub_create, sub_del, notify,
              time_func, sub_validate):
            sub_create.return_value = subnet
            sub_find.return_value = subnet
            time_func.return_value = deleted_at
            yield notify

    def test_create_subnet_notification(self):
        s = dict(network_id=1, cidr="192.168.10.0/24",
                 tenant_id=1, id=1, created_at="123")
        with self._stubs(s) as notify:
            self.plugin.create_subnet(self.context, dict(subnet=s))
            notify.assert_called_once_with(
                self.context,
                notifier_api.publisher_id("network"),
                "ip_block.create",
                notifier_api.CONF.default_notification_level,
                dict(tenant_id=s["tenant_id"],
                     ip_block_id=s["id"],
                     created_at=s["created_at"]))

    def test_delete_subnet_notification(self):
        now = time.strftime('%Y-%m-%d %H:%M:%S')
        later = time.strftime('%Y-%m-%d %H:%M:%S')
        s = dict(tenant_id=1, id=1, created_at=now)
        with self._stubs(s, deleted_at=later) as notify:
            self.plugin.delete_subnet(self.context, 1)
            notify.assert_called_once_with(
                self.context,
                notifier_api.publisher_id("network"),
                "ip_block.delete",
                notifier_api.CONF.default_notification_level,
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
            actual = self.plugin.diagnose_subnet(self.context, "*", None)
            self.assertEqual(expected, actual)

    def test_diagnose_subnet_with_wildcard_with_existing_subnets(self):
        subnet_id = str(uuid.uuid4())
        route = dict(id=1, cidr="0.0.0.0/0", gateway="192.168.0.1")

        subnet = dict(id=subnet_id, network_id=1, name=subnet_id,
                      tenant_id=self.context.tenant_id, ip_version=4,
                      cidr="192.168.0.0/24", gateway_ip="192.168.0.1",
                      dns_nameservers=[],
                      enable_dhcp=None)

        with self._stubs(subnets=[subnet], routes=[route]):
            actual = self.plugin.diagnose_subnet(self.context, "*", None)
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
            actual = self.plugin.diagnose_subnet(self.context, subnet_id, None)
            self.assertEqual(subnet["id"], actual["subnets"]["id"])
