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
import netaddr
from neutron.api.v2 import attributes as neutron_attrs
from neutron.common import exceptions
from neutron.db import api as db_api
from neutron.extensions import securitygroup as sg_ext
from oslo.config import cfg

from quark.db import api as quark_db_api
from quark.db import models
from quark import exceptions as quark_exceptions
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


class TestIpAddresses(TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, port, addr):
        port_model = None
        addr_model = None
        if port:
            port_model = models.Port()
            port_model.update(port)
        if addr:
            addr_model = models.IPAddress()
            addr_model.update(addr)
        with contextlib.nested(
            mock.patch("quark.db.api.port_find"),
            mock.patch("quark.ipam.QuarkIpam.allocate_ip_address")
        ) as (port_find, alloc_ip):
            port_find.return_value = port_model
            alloc_ip.return_value = addr_model
            yield

    def test_create_ip_address_by_network_and_device(self):
        port = dict(id=1, network_id=2, ip_addresses=[])
        ip = dict(id=1, address=3232235876, address_readable="192.168.1.100",
                  subnet_id=1, network_id=2, version=4,
                  tenant_id=self.context.tenant_id)
        with self._stubs(port=port, addr=ip):
            ip_address = dict(network_id=ip["network_id"],
                              device_ids=[4])
            response = self.plugin.create_ip_address(
                self.context, dict(ip_address=ip_address))

            self.assertIsNotNone(response["id"])
            self.assertEqual(response["network_id"], ip_address["network_id"])
            self.assertEqual(response["device_ids"], [""])
            self.assertEqual(response["port_ids"], [port["id"]])
            self.assertEqual(response["subnet_id"], ip["subnet_id"])
            self.assertEqual(response["tenant_id"], self.context.tenant_id)
            self.assertFalse(response["shared"])
            self.assertEqual(response["version"], 4)
            self.assertEqual(response["address"], "192.168.1.100")

    def test_create_ip_address_with_port(self):
        port = dict(id=1, network_id=2, ip_addresses=[])
        ip = dict(id=1, address=3232235876, address_readable="192.168.1.100",
                  subnet_id=1, network_id=2, version=4)
        with self._stubs(port=port, addr=ip):
            ip_address = dict(port_ids=[port["id"]])
            response = self.plugin.create_ip_address(
                self.context, dict(ip_address=ip_address))

            self.assertIsNotNone(response['id'])
            self.assertEqual(response['network_id'], ip["network_id"])
            self.assertEqual(response['port_ids'], [port["id"]])
            self.assertEqual(response['subnet_id'], ip['id'])

    def test_create_ip_address_by_device_no_network_fails(self):
        with self._stubs(port={}, addr=None):
            ip_address = dict(device_ids=[4])
            with self.assertRaises(exceptions.BadRequest):
                self.plugin.create_ip_address(self.context,
                                              dict(ip_address=ip_address))

    def test_create_ip_address_invalid_network_and_device(self):
        with self._stubs(port=None, addr=None):
            with self.assertRaises(exceptions.PortNotFound):
                ip_address = {'ip_address': {'network_id': 'fake',
                                             'device_id': 'fake'}}
                self.plugin.create_ip_address(self.context, ip_address)

    def test_create_ip_address_invalid_port(self):
        with self._stubs(port=None, addr=None):
            with self.assertRaises(exceptions.PortNotFound):
                ip_address = {'ip_address': {'port_id': 'fake'}}
                self.plugin.create_ip_address(self.context, ip_address)


class TestQuarkUpdateIPAddress(TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, ports, addr, addr_ports=False):
        port_models = []
        addr_model = None
        for port in ports:
            port_model = models.Port()
            port_model.update(port)
            port_models.append(port_model)
        if addr:
            addr_model = models.IPAddress()
            addr_model.update(addr)
            if addr_ports:
                addr_model.ports = port_models

        db_mod = "quark.db.api"
        with contextlib.nested(
            mock.patch("%s.port_find" % db_mod),
            mock.patch("%s.ip_address_find" % db_mod),
        ) as (port_find, ip_find):
            port_find.return_value = port_models
            ip_find.return_value = addr_model
            yield

    def test_update_ip_address_does_not_exist(self):
        with self._stubs(ports=[], addr=None):
            with self.assertRaises(exceptions.NotFound):
                self.plugin.update_ip_address(self.context,
                                              'no_ip_address_id',
                                              {'ip_address': {'port_ids': []}})

    def test_update_ip_address_port_not_found(self):
        ip = dict(id=1, address=3232235876, address_readable="192.168.1.100",
                  subnet_id=1, network_id=2, version=4)
        with self._stubs(ports=[], addr=ip):
            with self.assertRaises(exceptions.NotFound):
                ip_address = {'ip_address': {'port_ids': ['fake']}}
                self.plugin.update_ip_address(self.context,
                                              ip["id"],
                                              ip_address)

    def test_update_ip_address_specify_ports(self):
        port = dict(id=1, network_id=2, ip_addresses=[])
        ip = dict(id=1, address=3232235876, address_readable="192.168.1.100",
                  subnet_id=1, network_id=2, version=4)
        with self._stubs(ports=[port], addr=ip):
            ip_address = {'ip_address': {'port_ids': [port['id']]}}
            response = self.plugin.update_ip_address(self.context,
                                                     ip['id'],
                                                     ip_address)
            self.assertEqual(response['port_ids'], [port['id']])

    def test_update_ip_address_no_ports(self):
        port = dict(id=1, network_id=2, ip_addresses=[])
        ip = dict(id=1, address=3232235876, address_readable="192.168.1.100",
                  subnet_id=1, network_id=2, version=4)
        with self._stubs(ports=[port], addr=ip):
            ip_address = {'ip_address': {}}
            response = self.plugin.update_ip_address(self.context,
                                                     ip['id'],
                                                     ip_address)
            self.assertEqual(response['port_ids'], [])

    def test_update_ip_address_empty_ports_delete(self):
        port = dict(id=1, network_id=2, ip_addresses=[])
        ip = dict(id=1, address=3232235876, address_readable="192.168.1.100",
                  subnet_id=1, network_id=2, version=4)
        with self._stubs(ports=[port], addr=ip, addr_ports=True):
            ip_address = {'ip_address': {'port_ids': []}}
            response = self.plugin.update_ip_address(self.context,
                                                     ip['id'],
                                                     ip_address)
            self.assertEqual(response['port_ids'], [])


class TestQuarkGetPorts(TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, ports=None, addrs=None):
        port_models = []
        addr_models = None
        if addrs:
            addr_models = []
            for address in addrs:
                a = models.IPAddress()
                a.update(address)
                addr_models.append(a)

        if isinstance(ports, list):
            for port in ports:
                port_model = models.Port()
                port_model.update(port)
                if addr_models:
                    port_model.ip_addresses = addr_models
                port_models.append(port_model)
        elif ports is None:
            port_models = None
        else:
            port_model = models.Port()
            port_model.update(ports)
            if addr_models:
                port_model.ip_addresses = addr_models
            port_models = port_model

        db_mod = "quark.db.api"
        with contextlib.nested(
            mock.patch("%s.port_find" % db_mod)
        ) as (port_find,):
            port_find.return_value = port_models
            yield

    def test_port_list_no_ports(self):
        with self._stubs(ports=[]):
            ports = self.plugin.get_ports(self.context, filters=None,
                                          fields=None)
            self.assertEqual(ports, [])

    def test_port_list_with_ports(self):
        ip = dict(id=1, address=3232235876, address_readable="192.168.1.100",
                  subnet_id=1, network_id=2, version=4)
        port = dict(mac_address="aa:bb:cc:dd:ee:ff", network_id=1,
                    tenant_id=self.context.tenant_id, device_id=2)
        expected = {'status': None,
                    'device_owner': None,
                    'mac_address': 'aa:bb:cc:dd:ee:ff',
                    'network_id': 1,
                    'tenant_id': self.context.tenant_id,
                    'admin_state_up': None,
                    'device_id': 2}
        with self._stubs(ports=[port], addrs=[ip]):
            ports = self.plugin.get_ports(self.context, filters=None,
                                          fields=None)
            self.assertEqual(len(ports), 1)
            fixed_ips = ports[0].pop("fixed_ips")
            for key in expected.keys():
                self.assertEqual(ports[0][key], expected[key])
            self.assertEqual(fixed_ips[0]["subnet_id"], ip["subnet_id"])
            self.assertEqual(fixed_ips[0]["ip_address"],
                             ip["address_readable"])

    def test_port_show(self):
        ip = dict(id=1, address=3232235876, address_readable="192.168.1.100",
                  subnet_id=1, network_id=2, version=4)
        port = dict(mac_address="AA:BB:CC:DD:EE:FF", network_id=1,
                    tenant_id=self.context.tenant_id, device_id=2)
        expected = {'status': None,
                    'device_owner': None,
                    'mac_address': 'AA:BB:CC:DD:EE:FF',
                    'network_id': 1,
                    'tenant_id': self.context.tenant_id,
                    'admin_state_up': None,
                    'device_id': 2}
        with self._stubs(ports=port, addrs=[ip]):
            result = self.plugin.get_port(self.context, 1)
            fixed_ips = result.pop("fixed_ips")
            for key in expected.keys():
                self.assertEqual(result[key], expected[key])
            self.assertEqual(fixed_ips[0]["subnet_id"], ip["subnet_id"])
            self.assertEqual(fixed_ips[0]["ip_address"],
                             ip["address_readable"])

    def test_port_show_with_int_mac(self):
        port = dict(mac_address=187723572702975L, network_id=1,
                    tenant_id=self.context.tenant_id, device_id=2)
        expected = {'status': None,
                    'device_owner': None,
                    'mac_address': 'aa:bb:cc:dd:ee:ff',
                    'network_id': 1,
                    'tenant_id': self.context.tenant_id,
                    'admin_state_up': None,
                    'fixed_ips': [],
                    'device_id': 2}
        with self._stubs(ports=port):
            result = self.plugin.get_port(self.context, 1)
            for key in expected.keys():
                self.assertEqual(result[key], expected[key])

    def test_port_show_not_found(self):
        with self._stubs(ports=None):
            with self.assertRaises(exceptions.PortNotFound):
                self.plugin.get_port(self.context, 1)


class TestQuarkCreatePort(TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, port=None, network=None, addr=None, mac=None):
        port_model = models.Port()
        port_model.update(port)
        port_models = port_model

        db_mod = "quark.db.api"
        ipam = "quark.ipam.QuarkIpam"
        with contextlib.nested(
            mock.patch("%s.port_create" % db_mod),
            mock.patch("%s.network_find" % db_mod),
            mock.patch("%s.allocate_ip_address" % ipam),
            mock.patch("%s.allocate_mac_address" % ipam),
        ) as (port_create, net_find, alloc_ip, alloc_mac):
            port_create.return_value = port_models
            net_find.return_value = network
            alloc_ip.return_value = addr
            alloc_mac.return_value = mac
            yield port_create

    def test_create_port(self):
        network = dict(id=1)
        mac = dict(address="aa:bb:cc:dd:ee:ff")
        port_name = "foobar"
        ip = dict()
        port = dict(port=dict(mac_address=mac["address"], network_id=1,
                              tenant_id=self.context.tenant_id, device_id=2,
                              name=port_name))
        expected = {'status': None,
                    'name': port_name,
                    'device_owner': None,
                    'mac_address': mac["address"],
                    'network_id': network["id"],
                    'tenant_id': self.context.tenant_id,
                    'admin_state_up': None,
                    'fixed_ips': [],
                    'device_id': 2}
        with self._stubs(port=port["port"], network=network, addr=ip,
                         mac=mac) as port_create:
            result = self.plugin.create_port(self.context, port)
            self.assertTrue(port_create.called)
            for key in expected.keys():
                self.assertEqual(result[key], expected[key])

    def test_create_port_mac_address_not_specified(self):
        network = dict(id=1)
        mac = dict(address="aa:bb:cc:dd:ee:ff")
        ip = dict()
        port = dict(port=dict(mac_address=mac["address"], network_id=1,
                              tenant_id=self.context.tenant_id, device_id=2))
        expected = {'status': None,
                    'device_owner': None,
                    'mac_address': mac["address"],
                    'network_id': network["id"],
                    'tenant_id': self.context.tenant_id,
                    'admin_state_up': None,
                    'fixed_ips': [],
                    'device_id': 2}
        with self._stubs(port=port["port"], network=network, addr=ip,
                         mac=mac) as port_create:
            port["port"]["mac_address"] = neutron_attrs.ATTR_NOT_SPECIFIED
            result = self.plugin.create_port(self.context, port)
            self.assertTrue(port_create.called)
            for key in expected.keys():
                self.assertEqual(result[key], expected[key])

    def test_create_port_fixed_ips(self):
        network = dict(id=1)
        mac = dict(address="aa:bb:cc:dd:ee:ff")
        ip = mock.MagicMock()
        ip.get = lambda x, *y: 1 if x == "subnet_id" else None
        ip.formatted = lambda: "192.168.10.45"
        fixed_ips = [dict(subnet_id=1, ip_address="192.168.10.45")]
        port = dict(port=dict(mac_address=mac["address"], network_id=1,
                              tenant_id=self.context.tenant_id, device_id=2,
                              fixed_ips=fixed_ips, ip_addresses=[ip]))
        expected = {'status': None,
                    'device_owner': None,
                    'mac_address': mac["address"],
                    'network_id': network["id"],
                    'tenant_id': self.context.tenant_id,
                    'admin_state_up': None,
                    'fixed_ips': fixed_ips,
                    'device_id': 2}
        with self._stubs(port=port["port"], network=network, addr=ip,
                         mac=mac) as port_create:
            result = self.plugin.create_port(self.context, port)
            self.assertTrue(port_create.called)
            for key in expected.keys():
                self.assertEqual(result[key], expected[key])

    def test_create_port_fixed_ips_bad_request(self):
        network = dict(id=1)
        mac = dict(address="aa:bb:cc:dd:ee:ff")
        ip = mock.MagicMock()
        ip.get = lambda x: 1 if x == "subnet_id" else None
        ip.formatted = lambda: "192.168.10.45"
        fixed_ips = [dict()]
        port = dict(port=dict(mac_address=mac["address"], network_id=1,
                              tenant_id=self.context.tenant_id, device_id=2,
                              fixed_ips=fixed_ips, ip_addresses=[ip]))
        with self._stubs(port=port["port"], network=network, addr=ip,
                         mac=mac):
            with self.assertRaises(exceptions.BadRequest):
                self.plugin.create_port(self.context, port)

    def test_create_port_no_network_found(self):
        port = dict(port=dict(network_id=1, tenant_id=self.context.tenant_id,
                              device_id=2))
        with self._stubs(network=None, port=port["port"]):
            with self.assertRaises(exceptions.NetworkNotFound):
                self.plugin.create_port(self.context, port)

    def test_create_port_net_at_max(self):
        network = dict(id=1, ports=[models.Port()])
        mac = dict(address="aa:bb:cc:dd:ee:ff")
        port_name = "foobar"
        ip = dict()
        port = dict(port=dict(mac_address=mac["address"], network_id=1,
                              tenant_id=self.context.tenant_id, device_id=2,
                              name=port_name))
        with self._stubs(port=port["port"], network=network, addr=ip, mac=mac):
            with self.assertRaises(exceptions.OverQuota):
                self.plugin.create_port(self.context, port)

    def test_create_port_security_groups(self, groups=[1]):
        network = dict(id=1)
        mac = dict(address="aa:bb:cc:dd:ee:ff")
        port_name = "foobar"
        ip = dict()
        group = models.SecurityGroup()
        group.update({'id': 1, 'tenant_id': self.context.tenant_id,
                      'name': 'foo', 'description': 'bar'})
        port = dict(port=dict(mac_address=mac["address"], network_id=1,
                              tenant_id=self.context.tenant_id, device_id=2,
                              name=port_name, security_groups=[group]))
        expected = {'status': None,
                    'name': port_name,
                    'device_owner': None,
                    'mac_address': mac["address"],
                    'network_id': network["id"],
                    'tenant_id': self.context.tenant_id,
                    'admin_state_up': None,
                    'fixed_ips': [],
                    'security_groups': groups,
                    'device_id': 2}
        with self._stubs(port=port["port"], network=network, addr=ip,
                         mac=mac) as port_create:
            with mock.patch("quark.db.api.security_group_find") as group_find:
                group_find.return_value = (groups and group)
                port["port"]["security_groups"] = groups or [1]
                result = self.plugin.create_port(self.context, port)
                self.assertTrue(port_create.called)
                for key in expected.keys():
                    self.assertEqual(result[key], expected[key])

    def test_create_port_security_groups_not_found(self):
        with self.assertRaises(sg_ext.SecurityGroupNotFound):
            self.test_create_port_security_groups([])


class TestQuarkUpdatePort(TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, port):
        port_model = None
        if port:
            port_model = models.Port()
            port_model.update(port)
        with contextlib.nested(
            mock.patch("quark.db.api.port_find"),
            mock.patch("quark.db.api.port_update"),
            mock.patch("quark.ipam.QuarkIpam.allocate_ip_address"),
            mock.patch("quark.ipam.QuarkIpam.deallocate_ip_address")
        ) as (port_find, port_update, alloc_ip, dealloc_ip):
            port_find.return_value = port_model
            yield port_find, port_update, alloc_ip, dealloc_ip

    def test_update_port_not_found(self):
        with self._stubs(port=None):
            with self.assertRaises(exceptions.PortNotFound):
                self.plugin.update_port(self.context, 1, {})

    def test_update_port(self):
        with self._stubs(
            port=dict(id=1, name="myport")
        ) as (port_find, port_update, alloc_ip, dealloc_ip):
            new_port = dict(port=dict(name="ourport"))
            self.plugin.update_port(self.context, 1, new_port)
            self.assertEqual(port_find.call_count, 1)
            port_update.assert_called_once_with(
                self.context,
                port_find(),
                name="ourport",
                security_groups=[])

    def test_update_port_fixed_ip_bad_request(self):
        with self._stubs(
            port=dict(id=1, name="myport")
        ) as (port_find, port_update, alloc_ip, dealloc_ip):
            new_port = dict(port=dict(
                fixed_ips=[dict(subnet_id=None,
                                ip_address=None)]))
            with self.assertRaises(exceptions.BadRequest):
                self.plugin.update_port(self.context, 1, new_port)

    def test_update_port_fixed_ip(self):
        with self._stubs(
            port=dict(id=1, name="myport", mac_address="0:0:0:0:0:1")
        ) as (port_find, port_update, alloc_ip, dealloc_ip):
            new_port = dict(port=dict(
                fixed_ips=[dict(subnet_id=1,
                                ip_address="1.1.1.1")]))
            self.plugin.update_port(self.context, 1, new_port)
            self.assertEqual(dealloc_ip.call_count, 1)
            self.assertEqual(alloc_ip.call_count, 1)


class TestQuarkPostUpdatePort(TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, port, addr, addr2=None):
        port_model = None
        addr_model = None
        addr_model2 = None
        if port:
            port_model = models.Port()
            port_model.update(port)
        if addr:
            addr_model = models.IPAddress()
            addr_model.update(addr)
        if addr2:
            addr_model2 = models.IPAddress()
            addr_model2.update(addr2)
        with contextlib.nested(
            mock.patch("quark.db.api.port_find"),
            mock.patch("quark.ipam.QuarkIpam.allocate_ip_address"),
            mock.patch("quark.db.api.ip_address_find")
        ) as (port_find, alloc_ip, ip_find):
            port_find.return_value = port_model
            alloc_ip.return_value = addr_model2 if addr_model2 else addr_model
            ip_find.return_value = addr_model
            yield port_find, alloc_ip, ip_find

    def test_post_update_port_no_ports(self):
        with self.assertRaises(exceptions.PortNotFound):
            self.plugin.post_update_port(self.context, 1,
                                         {"port": {"network_id": 1}})

    def test_post_update_port_fixed_ips_empty_body(self):
        port = dict(port=dict(network_id=1, tenant_id=self.context.tenant_id,
                              device_id=2))
        with self._stubs(port=port, addr=None):
            with self.assertRaises(exceptions.BadRequest):
                self.plugin.post_update_port(self.context, 1, {})
            with self.assertRaises(exceptions.BadRequest):
                self.plugin.post_update_port(self.context, 1, {"port": {}})

    def test_post_update_port_fixed_ips_ip(self):
        new_port_ip = dict(port=dict(fixed_ips=[dict()]))
        port = dict(port=dict(network_id=1, tenant_id=self.context.tenant_id,
                              device_id=2))
        ip = dict(id=1, address=3232235876, address_readable="192.168.1.100",
                  subnet_id=1, network_id=2, version=4, deallocated=True)
        with self._stubs(port=port, addr=ip) as (port_find, alloc_ip, ip_find):
            response = self.plugin.post_update_port(self.context, 1,
                                                    new_port_ip)
            self.assertEqual(port_find.call_count, 1)
            self.assertEqual(alloc_ip.call_count, 1)
            self.assertEqual(ip_find.call_count, 0)
            self.assertEqual(response["fixed_ips"][0]["ip_address"],
                             "192.168.1.100")

    def test_post_update_port_fixed_ips_ip_id(self):
        new_port_ip = dict(port=dict(fixed_ips=[dict(ip_id=1)]))
        port = dict(port=dict(network_id=1, tenant_id=self.context.tenant_id,
                              device_id=2))
        ip = dict(id=1, address=3232235876, address_readable="192.168.1.100",
                  subnet_id=1, network_id=2, version=4, deallocated=True)
        with self._stubs(port=port, addr=ip) as (port_find, alloc_ip, ip_find):
            response = self.plugin.post_update_port(self.context, 1,
                                                    new_port_ip)
            self.assertEqual(port_find.call_count, 1)
            self.assertEqual(alloc_ip.call_count, 0)
            self.assertEqual(ip_find.call_count, 1)
            self.assertEqual(response["fixed_ips"][0]["ip_address"],
                             "192.168.1.100")

    def test_post_update_port_fixed_ips_ip_address_exists(self):
        new_port_ip = dict(port=dict(fixed_ips=[dict(
            ip_address="192.168.1.100")]))
        port = dict(port=dict(network_id=1, tenant_id=self.context.tenant_id,
                              device_id=2))
        ip = dict(id=1, address=3232235876, address_readable="192.168.1.100",
                  subnet_id=1, network_id=2, version=4, deallocated=True)
        with self._stubs(port=port, addr=ip) as (port_find, alloc_ip, ip_find):
            response = self.plugin.post_update_port(self.context, 1,
                                                    new_port_ip)
            self.assertEqual(port_find.call_count, 1)
            self.assertEqual(alloc_ip.call_count, 0)
            self.assertEqual(ip_find.call_count, 1)
            self.assertEqual(response["fixed_ips"][0]["ip_address"],
                             "192.168.1.100")

    def test_post_update_port_fixed_ips_ip_address_doesnt_exist(self):
        new_port_ip = dict(port=dict(fixed_ips=[dict(
            ip_address="192.168.1.101")]))
        port = dict(port=dict(network_id=1, tenant_id=self.context.tenant_id,
                              device_id=2))
        ip = dict(id=1, address=3232235876, address_readable="192.168.1.101",
                  subnet_id=1, network_id=2, version=4, deallocated=True)
        with self._stubs(port=port, addr=None, addr2=ip) as \
                (port_find, alloc_ip, ip_find):
            response = self.plugin.post_update_port(self.context, 1,
                                                    new_port_ip)
            self.assertEqual(port_find.call_count, 1)
            self.assertEqual(alloc_ip.call_count, 1)
            self.assertEqual(ip_find.call_count, 1)
            self.assertEqual(response["fixed_ips"][0]["ip_address"],
                             "192.168.1.101")


class TestQuarkGetPortCount(TestQuarkPlugin):
    def test_get_port_count(self):
        """This isn't really testable."""
        with mock.patch("quark.db.api.port_count_all"):
            self.plugin.get_ports_count(self.context, {})


class TestQuarkDeletePort(TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, port=None, addr=None, mac=None):
        port_models = None
        if port:
            port_model = models.Port()
            port_model.update(port)
            port_models = port_model

        db_mod = "quark.db.api"
        ipam = "quark.ipam.QuarkIpam"
        with contextlib.nested(
            mock.patch("%s.port_find" % db_mod),
            mock.patch("%s.deallocate_ip_address" % ipam),
            mock.patch("%s.deallocate_mac_address" % ipam),
            mock.patch("%s.port_delete" % db_mod),
            mock.patch("quark.drivers.base.BaseDriver.delete_port")
        ) as (port_find, dealloc_ip, dealloc_mac, db_port_del,
              driver_port_del):
            port_find.return_value = port_models
            dealloc_ip.return_value = addr
            dealloc_mac.return_value = mac
            yield db_port_del, driver_port_del

    def test_port_delete(self):
        port = dict(port=dict(network_id=1, tenant_id=self.context.tenant_id,
                              device_id=2, mac_address="AA:BB:CC:DD:EE:FF",
                              backend_key="foo"))
        with self._stubs(port=port["port"]) as (db_port_del, driver_port_del):
            self.plugin.delete_port(self.context, 1)
            self.assertTrue(db_port_del.called)
            driver_port_del.assert_called_with(self.context, "foo")

    def test_port_delete_port_not_found_fails(self):
        with self._stubs(port=None) as (db_port_del, driver_port_del):
            with self.assertRaises(exceptions.PortNotFound):
                self.plugin.delete_port(self.context, 1)


class TestQuarkDisassociatePort(TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, port=None):
        port_models = None
        if port:
            port_model = models.Port()
            port_model.update(port)
            for ip in port["fixed_ips"]:
                port_model.ip_addresses.append(models.IPAddress(
                    id=1,
                    address=ip["ip_address"],
                    subnet_id=ip["subnet_id"]))
            port_models = port_model

        db_mod = "quark.db.api"
        with mock.patch("%s.port_find" % db_mod) as port_find:
            port_find.return_value = port_models
            yield port_find

    def test_port_disassociate_port(self):
        ip = dict(id=1, address=3232235876, address_readable="192.168.1.100",
                  subnet_id=1, network_id=2, version=4)
        fixed_ips = [{"subnet_id": ip["subnet_id"],
                      "ip_address": ip["address_readable"]}]
        port = dict(port=dict(network_id=1, tenant_id=self.context.tenant_id,
                              device_id=2, mac_address="AA:BB:CC:DD:EE:FF",
                              backend_key="foo", fixed_ips=fixed_ips))
        with self._stubs(port=port["port"]) as (port_find):
            new_port = self.plugin.disassociate_port(self.context, 1, 1)
            port_find.assert_called_with(self.context,
                                         id=1,
                                         ip_address_id=[1],
                                         scope=quark_db_api.ONE)
            self.assertEqual(new_port["fixed_ips"], [])

    def test_port_disassociate_port_not_found_fails(self):
        with self._stubs(port=None):
            with self.assertRaises(exceptions.PortNotFound):
                self.plugin.disassociate_port(self.context, 1, 1)


class TestQuarkGetMacAddressRanges(TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, mac_range):
        db_mod = "quark.db.api"
        with mock.patch("%s.mac_address_range_find" % db_mod) as mar_find:
            mar_find.return_value = mac_range
            yield

    def test_find_mac_ranges(self):
        mar = dict(id=1, cidr="AA:BB:CC/24")
        with self._stubs([mar]):
            res = self.plugin.get_mac_address_ranges(self.context)
            self.assertEqual(res[0]["id"], mar["id"])
            self.assertEqual(res[0]["cidr"], mar["cidr"])

    def test_find_mac_range(self):
        mar = dict(id=1, cidr="AA:BB:CC/24")
        with self._stubs(mar):
            res = self.plugin.get_mac_address_range(self.context, 1)
            self.assertEqual(res["id"], mar["id"])
            self.assertEqual(res["cidr"], mar["cidr"])

    def test_find_mac_range_fail(self):
        with self._stubs(None):
            with self.assertRaises(quark_exceptions.MacAddressRangeNotFound):
                self.plugin.get_mac_address_range(self.context, 1)


class TestQuarkCreateMacAddressRanges(TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, mac_range):
        db_mod = "quark.db.api"
        with mock.patch("%s.mac_address_range_create" % db_mod) as mar_create:
            mar_create.return_value = mac_range
            yield

    def test_create_range(self):
        mar = dict(mac_address_range=dict(id=1, cidr="AA:BB:CC/24"))
        with self._stubs(mar["mac_address_range"]):
            res = self.plugin.create_mac_address_range(self.context, mar)
            self.assertEqual(res["id"], mar["mac_address_range"]["id"])
            self.assertEqual(res["cidr"], mar["mac_address_range"]["cidr"])

    def test_to_mac_range_cidr_format(self):
        cidr, first, last = self.plugin._to_mac_range("AA:BB:CC/24")
        first_mac = str(netaddr.EUI(first, dialect=netaddr.mac_unix))
        last_mac = str(netaddr.EUI(last, dialect=netaddr.mac_unix))
        self.assertEqual(cidr, "AA:BB:CC:00:00:00/24")
        self.assertEqual(first_mac, "aa:bb:cc:0:0:0")
        self.assertEqual(last_mac, "aa:bb:cd:0:0:0")

    def test_to_mac_range_just_prefix(self):
        cidr, first, last = self.plugin._to_mac_range("AA:BB:CC")
        first_mac = str(netaddr.EUI(first, dialect=netaddr.mac_unix))
        last_mac = str(netaddr.EUI(last, dialect=netaddr.mac_unix))
        self.assertEqual(cidr, "AA:BB:CC:00:00:00/24")
        self.assertEqual(first_mac, "aa:bb:cc:0:0:0")
        self.assertEqual(last_mac, "aa:bb:cd:0:0:0")

    def test_to_mac_range_unix_format(self):
        cidr, first, last = self.plugin._to_mac_range("AA-BB-CC")
        first_mac = str(netaddr.EUI(first, dialect=netaddr.mac_unix))
        last_mac = str(netaddr.EUI(last, dialect=netaddr.mac_unix))
        self.assertEqual(cidr, "AA:BB:CC:00:00:00/24")
        self.assertEqual(first_mac, "aa:bb:cc:0:0:0")
        self.assertEqual(last_mac, "aa:bb:cd:0:0:0")

    def test_to_mac_range_unix_cidr_format(self):
        cidr, first, last = self.plugin._to_mac_range("AA-BB-CC/24")
        first_mac = str(netaddr.EUI(first, dialect=netaddr.mac_unix))
        last_mac = str(netaddr.EUI(last, dialect=netaddr.mac_unix))
        self.assertEqual(cidr, "AA:BB:CC:00:00:00/24")
        self.assertEqual(first_mac, "aa:bb:cc:0:0:0")
        self.assertEqual(last_mac, "aa:bb:cd:0:0:0")

    def test_to_mac_prefix_too_short_fails(self):
        with self.assertRaises(quark_exceptions.InvalidMacAddressRange):
            cidr, first, last = self.plugin._to_mac_range("AA-BB")

    def test_to_mac_prefix_too_long_fails(self):
        with self.assertRaises(quark_exceptions.InvalidMacAddressRange):
            cidr, first, last = self.plugin._to_mac_range("AA-BB-CC-DD-EE-F0")

    def test_to_mac_prefix_is_garbage_fails(self):
        with self.assertRaises(quark_exceptions.InvalidMacAddressRange):
            cidr, first, last = self.plugin._to_mac_range("F0-0-BAR")


class TestQuarkDeleteMacAddressRanges(TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, mac_range):
        db_mod = "quark.db.api"
        with contextlib.nested(
            mock.patch("%s.mac_address_range_find" % db_mod),
            mock.patch("%s.mac_address_range_delete" % db_mod),
        ) as (mar_find, mar_delete):
            mar_find.return_value = mac_range
            yield mar_delete

    def test_mac_address_range_delete_not_found(self):
        with self._stubs(None):
            with self.assertRaises(quark_exceptions.MacAddressRangeNotFound):
                self.plugin.delete_mac_address_range(self.context, 1)

    def test_mac_address_range_delete_in_use(self):
        mar = mock.MagicMock()
        mar.id = 1
        mar.allocated_macs = 1
        with self._stubs(mar):
            with self.assertRaises(quark_exceptions.MacAddressRangeInUse):
                self.plugin.delete_mac_address_range(self.context, 1)

    def test_mac_address_range_delete_success(self):
        mar = mock.MagicMock()
        mar.id = 1
        mar.allocated_macs = 0
        with self._stubs(mar) as mar_delete:
            resp = self.plugin.delete_mac_address_range(self.context, 1)
            self.assertIsNone(resp)
            mar_delete.assert_called_once_with(self.context, mar)


class TestQuarkGetRoutes(TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, routes):
        with mock.patch("quark.db.api.route_find") as route_find:
            route_find.return_value = routes
            yield

    def test_get_routes(self):
        route = dict(id=1, cidr="192.168.0.0/24", gateway="192.168.0.1",
                     subnet_id=2)
        with self._stubs(routes=[route]):
            res = self.plugin.get_routes(self.context)
            for key in route.keys():
                self.assertEqual(res[0][key], route[key])

    def test_get_route(self):
        route = dict(id=1, cidr="192.168.0.0/24", gateway="192.168.0.1",
                     subnet_id=2)
        with self._stubs(routes=route):
            res = self.plugin.get_route(self.context, 1)
            for key in route.keys():
                self.assertEqual(res[key], route[key])

    def test_get_route_not_found_fails(self):
        with self._stubs(routes=None):
            with self.assertRaises(quark_exceptions.RouteNotFound):
                self.plugin.get_route(self.context, 1)


class TestQuarkCreateRoutes(TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, create_route, find_routes, subnet):
        db_mod = "quark.db.api"
        with contextlib.nested(
            mock.patch("%s.route_create" % db_mod),
            mock.patch("%s.route_find" % db_mod),
            mock.patch("%s.subnet_find" % db_mod)
        ) as (route_create, route_find, subnet_find):
            route_create.return_value = create_route
            route_find.return_value = find_routes
            subnet_find.return_value = subnet
            yield

    def test_create_route(self):
        subnet = dict(id=2)
        create_route = dict(id=1, cidr="172.16.0.0/24", gateway="172.16.0.1",
                            subnet_id=subnet["id"])
        route = dict(id=1, cidr="192.168.0.0/24", gateway="192.168.0.1",
                     subnet_id=subnet["id"])
        with self._stubs(create_route=create_route, find_routes=[route],
                         subnet=subnet):
            res = self.plugin.create_route(self.context,
                                           dict(route=create_route))
            for key in create_route.keys():
                self.assertEqual(res[key], create_route[key])

    def test_create_route_no_subnet_fails(self):
        subnet = dict(id=2)
        route = dict(id=1, cidr="192.168.0.0/24", gateway="192.168.0.1",
                     subnet_id=subnet["id"])
        with self._stubs(create_route=route, find_routes=[], subnet=None):
            with self.assertRaises(exceptions.SubnetNotFound):
                self.plugin.create_route(self.context, dict(route=route))

    def test_create_no_other_routes(self):
        subnet = dict(id=2)
        create_route = dict(id=1, cidr="192.168.0.0/24", gateway="192.168.0.1",
                            subnet_id=subnet["id"])
        with self._stubs(create_route=create_route, find_routes=[],
                         subnet=subnet):
            res = self.plugin.create_route(self.context,
                                           dict(route=create_route))
            self.assertEqual(res["cidr"], create_route["cidr"])

    def test_create_conflicting_route_raises(self):
        subnet = dict(id=2)
        create_route = dict(id=1, cidr="192.168.0.0/24", gateway="192.168.0.1",
                            subnet_id=subnet["id"])
        route = dict(id=1, cidr="192.168.0.0/24", gateway="192.168.0.1",
                     subnet_id=subnet["id"])
        with self._stubs(create_route=create_route, find_routes=[route],
                         subnet=subnet):
            with self.assertRaises(quark_exceptions.RouteConflict):
                self.plugin.create_route(self.context,
                                         dict(route=create_route))


class TestQuarkDeleteRoutes(TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, route):
        db_mod = "quark.db.api"
        with contextlib.nested(
            mock.patch("%s.route_delete" % db_mod),
            mock.patch("%s.route_find" % db_mod),
        ) as (route_delete, route_find):
            route_find.return_value = route
            yield route_delete

    def test_delete_route(self):
        route = dict(id=1, cidr="192.168.0.0/24", gateway="192.168.0.1",
                     subnet_id=2)
        with self._stubs(route=route) as route_delete:
            self.plugin.delete_route(self.context, 1)
            self.assertTrue(route_delete.called)

    def test_delete_route_not_found_fails(self):
        with self._stubs(route=None):
            with self.assertRaises(quark_exceptions.RouteNotFound):
                self.plugin.delete_route(self.context, 1)


class TestQuarkGetIpAddresses(TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, ips, ports):
        with mock.patch("quark.db.api.ip_address_find") as ip_find:
            ip_models = []
            port_models = []
            for port in ports:
                p = models.Port()
                p.update(port)
                port_models.append(p)
            if isinstance(ips, list):
                for ip in ips:
                    version = ip.pop("version")
                    ip_mod = models.IPAddress()
                    ip_mod.update(ip)
                    ip_mod.version = version
                    ip_mod.ports = port_models
                    ip_models.append(ip_mod)
                ip_find.return_value = ip_models
            else:
                if ips:
                    version = ips.pop("version")
                    ip_mod = models.IPAddress()
                    ip_mod.update(ips)
                    ip_mod.version = version
                    ip_mod.ports = port_models
                    ip_find.return_value = ip_mod
                else:
                    ip_find.return_value = ips
            yield

    def test_get_ip_addresses(self):
        port = dict(id=100, device_id="foobar")
        ip = dict(id=1, address=3232235876, address_readable="192.168.1.100",
                  subnet_id=1, network_id=2, version=4)
        with self._stubs(ips=[ip], ports=[port]):
            res = self.plugin.get_ip_addresses(self.context)
            addr_res = res[0]
            self.assertEqual(ip["id"], addr_res["id"])
            self.assertEqual(ip["subnet_id"], addr_res["subnet_id"])
            self.assertEqual(ip["address_readable"], addr_res["address"])
            self.assertEqual(addr_res["port_ids"][0], port["id"])
            self.assertEqual(addr_res["device_ids"][0], port["device_id"])

    def test_get_ip_address(self):
        port = dict(id=100)
        ip = dict(id=1, address=3232235876, address_readable="192.168.1.100",
                  subnet_id=1, network_id=2, version=4)
        with self._stubs(ips=ip, ports=[port]):
            res = self.plugin.get_ip_address(self.context, 1)
            self.assertEqual(ip["id"], res["id"])
            self.assertEqual(ip["subnet_id"], res["subnet_id"])
            self.assertEqual(ip["address_readable"], res["address"])
            self.assertEqual(res["port_ids"][0], port["id"])

    def test_get_ip_address_no_ip_fails(self):
        port = dict(id=100)
        with self._stubs(ips=None, ports=[port]):
            with self.assertRaises(quark_exceptions.IpAddressNotFound):
                self.plugin.get_ip_address(self.context, 1)


class TestQuarkCreateSecurityGroup(TestQuarkPlugin):
    def setUp(self, *args, **kwargs):
        super(TestQuarkCreateSecurityGroup, self).setUp(*args, **kwargs)
        cfg.CONF.set_override('quota_security_group', 1, 'QUOTAS')

    @contextlib.contextmanager
    def _stubs(self, security_group, other=0):
        dbgroup = models.SecurityGroup()
        dbgroup.update(security_group)

        with contextlib.nested(
                mock.patch("quark.db.api.security_group_find"),
                mock.patch("quark.db.api.security_group_create"),
        ) as (db_find, db_create):
            db_find.return_value.count.return_value = other
            db_create.return_value = dbgroup
            yield db_create

    def test_create_security_group(self):
        group = {'name': 'foo', 'description': 'bar',
                 'tenant_id': self.context.tenant_id}
        expected = {'name': 'foo', 'description': 'bar',
                    'tenant_id': self.context.tenant_id,
                    'security_group_rules': []}
        with self._stubs(group) as group_create:
            result = self.plugin.create_security_group(
                self.context, {'security_group': group})
            self.assertTrue(group_create.called)
            print "expected: %s but got: %s" % (expected, result)
            for key in expected.keys():
                self.assertEqual(result[key], expected[key])

    def test_create_default_security_group(self):
        group = {'name': 'default', 'description': 'bar',
                 'tenant_id': self.context.tenant_id}
        with self._stubs(group) as group_create:
            with self.assertRaises(sg_ext.SecurityGroupDefaultAlreadyExists):
                self.plugin.create_security_group(
                    self.context, {'security_group': group})
                self.assertTrue(group_create.called)


class TestQuarkDeleteSecurityGroup(TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, security_group=None):
        dbgroup = None
        if security_group:
            dbgroup = models.SecurityGroup()
            dbgroup.update(security_group)

        with contextlib.nested(
            mock.patch("quark.db.api.security_group_find"),
            mock.patch("quark.db.api.security_group_delete"),
            mock.patch(
                "quark.drivers.base.BaseDriver.delete_security_group")
        ) as (group_find, db_group_delete, driver_group_delete):
            group_find.return_value = dbgroup
            db_group_delete.return_value = dbgroup
            yield db_group_delete, driver_group_delete

    def test_delete_security_group(self):
        group = {'name': 'foo', 'description': 'bar', 'id': 1,
                 'tenant_id': self.context.tenant_id}
        with self._stubs(group) as (db_delete, driver_delete):
            self.plugin.delete_security_group(self.context, 1)
            self.assertTrue(db_delete.called)
            driver_delete.assert_called_once_with(self.context, 1)

    def test_delete_default_security_group(self):
        group = {'name': 'default', 'id': 1,
                 'tenant_id': self.context.tenant_id}
        with self._stubs(group) as (db_delete, driver_delete):
            with self.assertRaises(sg_ext.SecurityGroupCannotRemoveDefault):
                self.plugin.delete_security_group(self.context, 1)

    def test_delete_security_group_with_ports(self):
        port = models.Port()
        group = {'name': 'foo', 'description': 'bar', 'id': 1,
                 'tenant_id': self.context.tenant_id, 'ports': [port]}
        with self._stubs(group) as (db_delete, driver_delete):
            with self.assertRaises(sg_ext.SecurityGroupInUse):
                self.plugin.delete_security_group(self.context, 1)

    def test_delete_security_group_not_found(self):
        with self._stubs() as (db_delete, driver_delete):
            with self.assertRaises(sg_ext.SecurityGroupNotFound):
                self.plugin.delete_security_group(self.context, 1)


class TestQuarkCreateSecurityGroupRule(TestQuarkPlugin):
    def setUp(self, *args, **kwargs):
        super(TestQuarkCreateSecurityGroupRule, self).setUp(*args, **kwargs)
        cfg.CONF.set_override('quota_security_group_rule', 1, 'QUOTAS')
        cfg.CONF.set_override('quota_security_rules_per_group', 1, 'QUOTAS')
        self.rule = {'id': 1, 'ethertype': 'IPv4',
                     'security_group_id': 1, 'group': {'id': 1},
                     'protocol': None, 'port_range_min': None,
                     'port_range_max': None}
        self.expected = {
            'id': 1,
            'remote_group_id': None,
            'direction': None,
            'port_range_min': None,
            'port_range_max': None,
            'remote_ip_prefix': None,
            'ethertype': 'IPv4',
            'tenant_id': None,
            'protocol': None,
            'security_group_id': 1}

    @contextlib.contextmanager
    def _stubs(self, rule, group):
        dbrule = models.SecurityGroupRule()
        dbrule.update(rule)
        dbrule.group_id = rule['security_group_id']
        dbgroup = None
        if group:
            dbgroup = models.SecurityGroup()
            dbgroup.update(group)

        with contextlib.nested(
                mock.patch("quark.db.api.security_group_find"),
                mock.patch("quark.db.api.security_group_rule_find"),
                mock.patch("quark.db.api.security_group_rule_create")
        ) as (group_find, rule_find, rule_create):
            group_find.return_value = dbgroup
            rule_find.return_value.count.return_value = group.get(
                'port_rules', None) if group else 0
            rule_create.return_value = dbrule
            yield rule_create

    def _test_create_security_rule(self, **ruleset):
        ruleset['tenant_id'] = self.context.tenant_id
        rule = dict(self.rule, **ruleset)
        group = rule.pop('group')
        expected = dict(self.expected, **ruleset)
        expected.pop('group', None)
        with self._stubs(rule, group) as rule_create:
            result = self.plugin.create_security_group_rule(
                self.context, {'security_group_rule': rule})
            self.assertTrue(rule_create.called)
            print "expected: %s but got: %s" % (expected, result)
            for key in expected.keys():
                self.assertEqual(expected[key], result[key])

    def test_create_security_rule_IPv6(self):
        self._test_create_security_rule(ethertype='IPv6')

    def test_create_security_rule_UDP(self):
        self._test_create_security_rule(protocol=17)

    def test_create_security_rule_UDP_string(self):
        self._test_create_security_rule(protocol="UDP")

    def test_create_security_rule_bad_string_fail(self):
        self.assertRaises(sg_ext.SecurityGroupRuleInvalidProtocol,
                          self._test_create_security_rule, protocol="DERP")

    def test_create_security_rule_TCP(self):
        self._test_create_security_rule(protocol=6)

    def test_create_security_rule_remote_ip(self):
        self._test_create_security_rule(remote_ip_prefix='192.168.0.1')

    def test_create_security_rule_remote_group(self):
        self._test_create_security_rule(remote_group_id=2)

    def test_create_security_rule_port_range_invalid_ranges_fails(self):
        with self.assertRaises(exceptions.InvalidInput):
            self._test_create_security_rule(protocol=6, port_range_min=0)

    def test_create_security_group_no_proto_with_ranges_fails(self):
        with self.assertRaises(sg_ext.SecurityGroupProtocolRequiredWithPorts):
            self._test_create_security_rule(protocol=None, port_range_min=0)
        with self.assertRaises(Exception):
            self._test_create_security_rule(
                protocol=6, port_range_min=1, port_range_max=0)

    def test_create_security_rule_remote_conflicts(self):
        with self.assertRaises(Exception):
            self._test_create_security_rule(remote_ip_prefix='192.168.0.1',
                                            remote_group_id='0')

    def test_create_security_rule_min_greater_than_max_fails(self):
        with self.assertRaises(sg_ext.SecurityGroupInvalidPortRange):
            self._test_create_security_rule(protocol=6, port_range_min=10,
                                            port_range_max=9)

    def test_create_security_rule_no_group(self):
        with self.assertRaises(sg_ext.SecurityGroupNotFound):
            self._test_create_security_rule(group=None)

    def test_create_security_rule_group_at_max(self):
        with self.assertRaises(exceptions.OverQuota):
            self._test_create_security_rule(
                group={'id': 1, 'rules': [models.SecurityGroupRule()]})


class TestQuarkDeleteSecurityGroupRule(TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, rule={}, group={'id': 1}):
        dbrule = None
        dbgroup = None
        if group:
            dbgroup = models.SecurityGroup()
            dbgroup.update(group)
        if rule:
            dbrule = models.SecurityGroupRule()
            dbrule.update(dict(rule, group=dbgroup))
        print rule

        with contextlib.nested(
                mock.patch("quark.db.api.security_group_find"),
                mock.patch("quark.db.api.security_group_rule_find"),
                mock.patch("quark.db.api.security_group_rule_delete"),
                mock.patch(
                    "quark.drivers.base.BaseDriver.delete_security_group_rule")
        ) as (group_find, rule_find, db_group_delete, driver_group_delete):
            group_find.return_value = dbgroup
            rule_find.return_value = dbrule
            yield db_group_delete, driver_group_delete

    def test_delete_security_group_rule(self):
        rule = {'id': 1, 'security_group_id': 1, 'ethertype': 'IPv4',
                'protocol': 6, 'port_range_min': 0, 'port_range_max': 10,
                'direction': 'ingress', 'tenant_id': self.context.tenant_id}
        expected = {
            'id': 1, 'ethertype': 'IPv4', 'security_group_id': 1,
            'direction': 'ingress', 'port_range_min': 0, 'port_range_max': 10,
            'remote_group_id': None, 'remote_ip_prefix': None,
            'tenant_id': self.context.tenant_id, 'protocol': 6}

        with self._stubs(dict(rule, group_id=1)) as (db_delete, driver_delete):
            self.plugin.delete_security_group_rule(self.context, 1)
            self.assertTrue(db_delete.called)
            driver_delete.assert_called_once_with(self.context, 1,
                                                  expected)

    def test_delete_security_group_rule_rule_not_found(self):
        with self._stubs() as (db_delete, driver_delete):
            with self.assertRaises(sg_ext.SecurityGroupRuleNotFound):
                self.plugin.delete_security_group_rule(self.context, 1)

    def test_delete_security_group_rule_group_not_found(self):
        rule = {'id': 1, 'security_group_id': 1, 'ethertype': 'IPv4'}
        with self._stubs(dict(rule, group_id=1),
                         None) as (db_delete, driver_delete):
            with self.assertRaises(sg_ext.SecurityGroupNotFound):
                self.plugin.delete_security_group_rule(self.context, 1)


class TestQuarkGetIpPolicies(TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, ip_policy):
        db_mod = "quark.db.api"
        with mock.patch("%s.ip_policy_find" % db_mod) as ip_policy_find:
            ip_policy_find.return_value = ip_policy
            yield

    def test_get_ip_policy_not_found(self):
        with self._stubs(None):
            with self.assertRaises(quark_exceptions.IPPolicyNotFound):
                self.plugin.get_ip_policy(self.context, 1)

    def test_get_ip_policy(self):
        address = int(netaddr.IPAddress("1.1.1.1"))
        ip_policy = dict(
            id=1,
            subnet_id=1,
            network_id=2,
            exclude=[dict(address=address, prefix=24)])
        with self._stubs(ip_policy):
            resp = self.plugin.get_ip_policy(self.context, 1)
            self.assertEqual(len(resp.keys()), 4)
            self.assertEqual(resp["id"], 1)
            self.assertEqual(resp["subnet_id"], 1)
            self.assertEqual(resp["network_id"], 2)
            self.assertEqual(resp["exclude"], ["1.1.1.1/24"])

    def test_get_ip_policies(self):
        address = int(netaddr.IPAddress("1.1.1.1"))
        ip_policy = dict(
            id=1,
            subnet_id=1,
            network_id=2,
            exclude=[dict(address=address, prefix=24)])
        with self._stubs([ip_policy]):
            resp = self.plugin.get_ip_policies(self.context)
            self.assertEqual(len(resp), 1)
            resp = resp[0]
            self.assertEqual(len(resp.keys()), 4)
            self.assertEqual(resp["id"], 1)
            self.assertEqual(resp["subnet_id"], 1)
            self.assertEqual(resp["network_id"], 2)
            self.assertEqual(resp["exclude"], ["1.1.1.1/24"])


class TestQuarkCreateIpPolicies(TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, ip_policy, subnet=None, net=None):
        db_mod = "quark.db.api"
        with contextlib.nested(
            mock.patch("%s.subnet_find" % db_mod),
            mock.patch("%s.network_find" % db_mod),
            mock.patch("%s.ip_policy_create" % db_mod),
        ) as (subnet_find, net_find, ip_policy_create):
            subnet_find.return_value = subnet
            net_find.return_value = net
            ip_policy_create.return_value = ip_policy
            yield ip_policy_create

    def test_create_ip_policy_invalid_body_missing_exclude(self):
        with self._stubs(None):
            with self.assertRaises(exceptions.BadRequest):
                self.plugin.create_ip_policy(self.context, dict(
                    ip_policy=dict()))

    def test_create_ip_policy_invalid_body_missing_netsubnet(self):
        with self._stubs(None):
            with self.assertRaises(exceptions.BadRequest):
                self.plugin.create_ip_policy(self.context, dict(
                    ip_policy=dict(exclude=["1.1.1.1/24"])))

    def test_create_ip_policy_invalid_subnet(self):
        with self._stubs(None):
            with self.assertRaises(exceptions.SubnetNotFound):
                self.plugin.create_ip_policy(self.context, dict(
                    ip_policy=dict(subnet_id=1,
                                   exclude=["1.1.1.1/24"])))

    def test_create_ip_policy_invalid_network(self):
        with self._stubs(None):
            with self.assertRaises(exceptions.NetworkNotFound):
                self.plugin.create_ip_policy(self.context, dict(
                    ip_policy=dict(network_id=1,
                                   exclude=["1.1.1.1/24"])))

    def test_create_ip_policy_network_ip_policy_already_exists(self):
        with self._stubs(None, net=dict(id=1, ip_policy=dict(id=2))):
            with self.assertRaises(quark_exceptions.IPPolicyAlreadyExists):
                self.plugin.create_ip_policy(self.context, dict(
                    ip_policy=dict(network_id=1,
                                   exclude=["1.1.1.1/24"])))

    def test_create_ip_policy_subnet_ip_policy_already_exists(self):
        with self._stubs(None, subnet=dict(id=1, ip_policy=dict(id=2))):
            with self.assertRaises(quark_exceptions.IPPolicyAlreadyExists):
                self.plugin.create_ip_policy(self.context, dict(
                    ip_policy=dict(subnet_id=1,
                                   exclude=["1.1.1.1/24"])))

    def test_create_ip_policy_network(self):
        ipp = dict(subnet_id=None, network_id=1,
                   exclude=[dict(address=int(netaddr.IPAddress("1.1.1.1")),
                                 prefix=24)])
        with self._stubs(ipp, net=dict(id=1, ip_policy=dict(id=2))):
            with self.assertRaises(quark_exceptions.IPPolicyAlreadyExists):
                resp = self.plugin.create_ip_policy(self.context, dict(
                    ip_policy=dict(network_id=1,
                                   exclude=["1.1.1.1/24"])))
                self.assertEqual(len(resp.keys()), 3)
                self.assertIsNone(resp["subnet_id"])
                self.assertEqual(resp["network_id"], 1)
                self.assertEqual(resp["exclude"], ["1.1.1.1/24"])

    def test_create_ip_policy_subnet(self):
        ipp = dict(subnet_id=1, network_id=None,
                   exclude=[dict(address=int(netaddr.IPAddress("1.1.1.1")),
                                 prefix=24)])
        with self._stubs(ipp, subnet=dict(id=1, ip_policy=dict(id=2))):
            with self.assertRaises(quark_exceptions.IPPolicyAlreadyExists):
                resp = self.plugin.create_ip_policy(self.context, dict(
                    ip_policy=dict(subnet_id=1,
                                   exclude=["1.1.1.1/24"])))
                self.assertEqual(len(resp.keys()), 3)
                self.assertEqual(resp["subnet_id"], 1)
                self.assertIsNone(resp["network_id"])
                self.assertEqual(resp["exclude"], ["1.1.1.1/24"])


class TestQuarkDeleteIpPolicies(TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, ip_policy):
        db_mod = "quark.db.api"
        with contextlib.nested(
            mock.patch("%s.ip_policy_find" % db_mod),
            mock.patch("%s.ip_policy_delete" % db_mod),
        ) as (ip_policy_find, ip_policy_delete):
            ip_policy_find.return_value = ip_policy
            yield ip_policy_find, ip_policy_delete

    def test_delete_ip_policy_not_found(self):
        with self._stubs(None):
            with self.assertRaises(quark_exceptions.IPPolicyNotFound):
                self.plugin.delete_ip_policy(self.context, 1)

    def test_delete_ip_policy(self):
        address = int(netaddr.IPAddress("1.1.1.1"))
        ip_policy = dict(
            id=1,
            subnet_id=1,
            network_id=2,
            exclude=[dict(address=address, prefix=24)])
        with self._stubs(ip_policy) as (ip_policy_find, ip_policy_delete):
            self.plugin.delete_ip_policy(self.context, 1)
            self.assertEqual(ip_policy_find.call_count, 1)
            self.assertEqual(ip_policy_delete.call_count, 1)
