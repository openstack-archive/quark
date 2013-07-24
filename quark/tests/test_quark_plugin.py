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

import uuid

import contextlib
import copy
import mock
from neutron.api.v2 import attributes as neutron_attrs
from neutron.common import exceptions
from neutron.db import api as db_api
from oslo.config import cfg

from quark.db import models
import quark.plugin

from quark.tests import test_base


class TestQuarkPlugin(test_base.TestBase):
    def setUp(self):
        super(TestQuarkPlugin, self).setUp()

        cfg.CONF.set_override('quota_ports_per_network', 1, 'QUOTAS')
        cfg.CONF.set_override('connection', 'sqlite://', 'database')
        db_api.configure_db()
        self.plugin = quark.plugin.Plugin()

    def tearDown(self):
        db_api.clear_db()


class TestQuarkGetSubnetCount(TestQuarkPlugin):
    def test_get_subnet_count(self):
        """This isn't really testable."""
        with mock.patch("quark.db.api.subnet_count_all"):
            self.plugin.get_subnets_count(self.context, {})


class TestQuarkAPIExtensions(TestQuarkPlugin):
    """Adds coverage for appending the API extension path."""
    def test_append_quark_extensions(self):
        conf = mock.MagicMock()
        conf.__contains__.return_value = False
        quark.plugin.append_quark_extensions(conf)
        self.assertEqual(conf.set_override.call_count, 0)

    def test_append_no_extension_path(self):
        conf = mock.MagicMock()
        conf.__contains__.return_value = True
        with mock.patch("quark.plugin.extensions") as extensions:
            extensions.__path__ = ["apple", "banana", "carrot"]
            quark.plugin.append_quark_extensions(conf)
            conf.__contains__.assert_called_once_with("api_extensions_path")
            conf.set_override.assert_called_once_with(
                "api_extensions_path",
                "apple:banana:carrot")


class TestQuarkGetSubnets(TestQuarkPlugin):
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


class TestQuarkCreateSubnetOverlapping(TestQuarkPlugin):
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


class TestQuarkCreateSubnetAllocationPools(TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, subnet):
        s = models.Subnet(network=models.Network(id=1, subnets=[]))
        s.update(subnet)

        with contextlib.nested(
            mock.patch("quark.db.api.network_find"),
            mock.patch("quark.db.api.subnet_find"),
            mock.patch("quark.db.api.subnet_create")
        ) as (net_find, subnet_find, subnet_create):
            net_find.return_value = s["network"]
            subnet_find.return_value = []
            subnet_create.return_value = s
            yield subnet_create

    def test_create_subnet_allocation_pools_zero(self):
        s = dict(subnet=dict(
            cidr="192.168.1.1/24",
            network_id=1))
        with self._stubs(s["subnet"]) as subnet_create:
            resp = self.plugin.create_subnet(self.context, s)
            self.assertEqual(subnet_create.call_count, 1)
            self.assertEqual(resp["allocation_pools"],
                             [dict(start="192.168.1.0", end="192.168.1.255")])

    def test_create_subnet_allocation_pools_one(self):
        pools = [dict(start="192.168.1.10", end="192.168.1.20")]
        s = dict(subnet=dict(
            allocation_pools=pools,
            cidr="192.168.1.1/24",
            network_id=1))
        with self._stubs(s["subnet"]) as subnet_create:
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
        with self._stubs(s["subnet"]) as subnet_create:
            resp = self.plugin.create_subnet(self.context, s)
            self.assertEqual(subnet_create.call_count, 1)
            self.assertEqual(resp["allocation_pools"], pools)


# TODO(amir): Refactor the tests to test individual subnet attributes.
# * copy.deepcopy was necessary to maintain tests on keys, which is a bit ugly.
# * workaround is also in place for lame ATTR_NOT_SPECIFIED object()
class TestQuarkCreateSubnet(TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, subnet=None, network=None, routes=None, dns=None):
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


class TestQuarkUpdateSubnet(TestQuarkPlugin):
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


class TestQuarkDeleteSubnet(TestQuarkPlugin):
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


class TestQuarkGetNetworks(TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, nets=None, subnets=None):
        net_mods = []
        subnet_mods = []

        for subnet in subnets:
            subnet_mod = models.Subnet()
            subnet_mod.update(subnet)
            subnet_mods.append(subnet_mod)

        if isinstance(nets, list):
            for net in nets:
                net_mod = models.Network()
                net_mod.update(net)
                net_mod["subnets"] = subnet_mods
                net_mods.append(net_mod)
        else:
            if nets:
                net_mods = nets.copy()
                net_mods["subnets"] = subnet_mods
            else:
                net_mods = nets

        db_mod = "quark.db.api"
        with mock.patch("%s.network_find" % db_mod) as net_find:
            net_find.return_value = net_mods
            yield

    def test_get_networks(self):
        subnet = dict(id=1)
        net = dict(id=1, tenant_id=self.context.tenant_id, name="public",
                   status="active")
        with self._stubs(nets=[net], subnets=[subnet]):
            nets = self.plugin.get_networks(self.context, {})
            for key in net.keys():
                self.assertEqual(nets[0][key], net[key])
            self.assertEqual(nets[0]["subnets"][0], 1)

    def test_get_network(self):
        subnet = dict(id=1)
        net = dict(id=1, tenant_id=self.context.tenant_id, name="public",
                   status="active")
        expected = net.copy()
        expected["admin_state_up"] = None
        expected["shared"] = False
        expected["status"] = "active"
        with self._stubs(nets=net, subnets=[subnet]):
            res = self.plugin.get_network(self.context, 1)
            for key in expected.keys():
                self.assertEqual(res[key], expected[key])
            self.assertEqual(res["subnets"][0], 1)

    def test_get_network_no_network_fails(self):
        with self._stubs(nets=None, subnets=[]):
            with self.assertRaises(exceptions.NetworkNotFound):
                self.plugin.get_network(self.context, 1)


class TestQuarkGetNetworkCount(TestQuarkPlugin):
    def test_get_port_count(self):
        """This isn't really testable."""
        with mock.patch("quark.db.api.network_count_all"):
            self.plugin.get_networks_count(self.context, {})


class TestQuarkUpdateNetwork(TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, net=None):
        net_mod = net
        if net:
            net_mod = net.copy()

        db_mod = "quark.db.api"
        with contextlib.nested(
            mock.patch("%s.network_find" % db_mod),
            mock.patch("%s.network_update" % db_mod)
        ) as (net_find, net_update):
            net_find.return_value = net_mod
            net_update.return_value = net_mod
            yield net_update

    def test_update_network(self):
        net = dict(id=1)
        with self._stubs(net=net) as net_update:
            self.plugin.update_network(self.context, 1, dict(network=net))
            self.assertTrue(net_update.called)

    def test_update_network_not_found_fails(self):
        with self._stubs(net=None):
            with self.assertRaises(exceptions.NetworkNotFound):
                self.plugin.update_network(self.context, 1, None)


class TestQuarkDeleteNetwork(TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, net=None, ports=None, subnets=None):
        subnets = subnets or []
        net_mod = net
        port_mods = []
        subnet_mods = []

        for port in ports:
            port_model = models.Port()
            port_model.update(port)
            port_mods.append(port_model)

        for subnet in subnets:
            subnet_mod = models.Subnet()
            subnet_mod.update(subnet)
            subnet_mods.append(subnet_mod)

        if net:
            net_mod = models.Network()
            net_mod.update(net)
            net_mod.ports = port_mods
            net_mod["subnets"] = subnet_mods

        db_mod = "quark.db.api"
        with contextlib.nested(
            mock.patch("%s.network_find" % db_mod),
            mock.patch("%s.network_delete" % db_mod),
            mock.patch("quark.drivers.base.BaseDriver.delete_network"),
            mock.patch("%s.subnet_delete" % db_mod)
        ) as (net_find, net_delete, driver_net_delete, subnet_del):
            net_find.return_value = net_mod
            yield net_delete

    def test_delete_network(self):
        net = dict(id=1)
        with self._stubs(net=net, ports=[]) as net_delete:
            self.plugin.delete_network(self.context, 1)
            self.assertTrue(net_delete.called)

    def test_delete_network_with_ports_fails(self):
        net = dict(id=1)
        port = dict(id=2)
        with self._stubs(net=net, ports=[port]):
            with self.assertRaises(exceptions.NetworkInUse):
                self.plugin.delete_network(self.context, 1)

    def test_delete_network_not_found_fails(self):
        with self._stubs(net=None, ports=[]):
            with self.assertRaises(exceptions.NetworkNotFound):
                self.plugin.delete_network(self.context, 1)

    def test_delete_network_with_subnets_passes(self):
        net = dict(id=1)
        subnet = dict(id=1)
        with self._stubs(net=net, ports=[], subnets=[subnet]) as net_delete:
            self.plugin.delete_network(self.context, 1)
            self.assertTrue(net_delete.called)


class TestQuarkCreateNetwork(TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, net=None, subnet=None, ports=None):
        net_mod = net
        subnet_mod = None
        if net:
            net_mod = models.Network()
            net_mod.update(net)

        if subnet:
            subnet_mod = models.Subnet()
            subnet_mod.update(subnet)

        db_mod = "quark.db.api"
        with contextlib.nested(
            mock.patch("%s.network_create" % db_mod),
            mock.patch("%s.subnet_create" % db_mod),
            mock.patch("quark.drivers.base.BaseDriver.create_network"),
        ) as (net_create, sub_create, driver_net_create):
            net_create.return_value = net_mod
            sub_create.return_value = subnet_mod
            yield net_create

    def test_create_network(self):
        net = dict(id=1, name="public", admin_state_up=True,
                   tenant_id=0)
        with self._stubs(net=net) as net_create:
            net = self.plugin.create_network(self.context, dict(network=net))
            self.assertTrue(net_create.called)
            self.assertEqual(len(net.keys()), 7)
            self.assertIsNotNone(net["id"])
            self.assertEqual(net["name"], "public")
            self.assertIsNone(net["admin_state_up"])
            self.assertIsNone(net["status"])
            self.assertEqual(net["subnets"], [])
            self.assertEqual(net["shared"], False)
            self.assertEqual(net["tenant_id"], 0)
