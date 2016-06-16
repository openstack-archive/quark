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

import contextlib
import mock
from neutron.common import exceptions as n_exc_ext
from oslo_config import cfg
from quark import exceptions as q_exc

import quark.ipam
# import below necessary if file run by itself
from quark import plugin  # noqa
import quark.plugin_modules.ip_policies as policy_api
import quark.plugin_modules.networks as network_api
import quark.plugin_modules.routes as routes_api
import quark.plugin_modules.subnets as subnet_api
from quark.tests.functional.base import BaseFunctionalTest

CONF = cfg.CONF


class QuarkCreateRoutes(BaseFunctionalTest):
    @contextlib.contextmanager
    def _stubs(self, network, subnet, ip_policy):
        self.ipam = quark.ipam.QuarkIpamANY()
        with contextlib.nested(mock.patch("neutron.common.rpc.get_notifier")):
            net = network_api.create_network(self.context, network)
            subnet['subnet']['network_id'] = net['id']
            sub1 = subnet_api.create_subnet(self.context, subnet)
            ipp = policy_api.update_ip_policy(self.context,
                                              sub1["ip_policy_id"], ip_policy)
            yield net, sub1, ipp

    def test_create_route(self):
        cidr = "192.168.0.0/24"
        ip_policy = dict(exclude=["192.168.0.1/32"])
        ip_policy = {"ip_policy": ip_policy}
        network = dict(name="public", tenant_id="fake", network_plugin="BASE")
        network = {"network": network}
        subnet = dict(ip_version=4, next_auto_assign_ip=2,
                      cidr=cidr, ip_policy=None,
                      tenant_id="fake")
        subnet = {"subnet": subnet}
        create_route = dict(cidr="172.16.0.0/24", gateway="172.16.0.1")
        with self._stubs(network, subnet, ip_policy) as (net, sub, ipp):
            self.assertIsNotNone(net)
            self.assertIsNotNone(sub)
            self.assertIsNotNone(ipp)
            create_route["subnet_id"] = sub["id"]
            new_route = routes_api.create_route(self.context,
                                                dict(route=create_route))
            self.assertIsNotNone(new_route["id"])
            for key in create_route.keys():
                self.assertEqual(new_route[key], create_route[key])

    def test_create_route_gateway_conflict_raises(self):
        cidr = "192.168.0.0/24"
        ip_policy = dict(exclude=["192.168.0.0/32", "192.168.0.255/32"])
        ip_policy = {"ip_policy": ip_policy}
        network = dict(name="public", tenant_id="fake", network_plugin="BASE")
        network = {"network": network}
        subnet = dict(ip_version=4, next_auto_assign_ip=2,
                      cidr=cidr, ip_policy=None,
                      tenant_id="fake")
        create_route = dict(cidr="192.168.0.0/24", gateway="192.168.0.1")
        subnet = {"subnet": subnet}
        with self._stubs(network, subnet, ip_policy) as (net, sub, ipp):
            self.assertIsNotNone(net)
            self.assertIsNotNone(sub)
            self.assertIsNotNone(ipp)
            create_route["subnet_id"] = sub["id"]
            with self.assertRaises(
                    n_exc_ext.GatewayConflictWithAllocationPools):
                routes_api.create_route(self.context,
                                        dict(route=create_route))

    def test_create_no_other_routes(self):
        cidr = "192.168.0.0/24"
        ip_policy = dict(exclude=["192.168.0.0/32", "192.168.0.1/32",
                                  "192.168.0.255/32"])
        ip_policy = {"ip_policy": ip_policy}
        network = dict(name="public", tenant_id="fake", network_plugin="BASE")
        network = {"network": network}
        subnet = dict(ip_version=4, cidr=cidr, ip_policy=None,
                      tenant_id="fake")
        create_route = dict(cidr="192.168.0.0/24", gateway="192.168.0.1")
        subnet = {"subnet": subnet}
        with self._stubs(network, subnet, ip_policy) as (net, sub, ipp):
            self.assertIsNotNone(net)
            self.assertIsNotNone(sub)
            self.assertIsNotNone(ipp)
            create_route["subnet_id"] = sub["id"]
            route = routes_api.create_route(self.context,
                                            dict(route=create_route))
            for key in create_route.keys():
                self.assertEqual(create_route[key], route[key])

    def test_create_conflicting_route_raises(self):
        cidr = "192.168.0.0/24"
        ip_policy = dict(exclude=["192.168.0.1/32"])
        ip_policy = {"ip_policy": ip_policy}
        network = dict(name="public", tenant_id="fake", network_plugin="BASE")
        network = {"network": network}
        subnet = dict(ip_version=4, next_auto_assign_ip=2,
                      cidr=cidr, ip_policy=None,
                      tenant_id="fake")
        create_route = dict(cidr="172.16.0.0/24", gateway="172.16.0.1")
        subnet = {"subnet": subnet}
        with self._stubs(network, subnet, ip_policy) as (net, sub, ipp):
            self.assertIsNotNone(net)
            self.assertIsNotNone(sub)
            self.assertIsNotNone(ipp)
            create_route["subnet_id"] = sub["id"]
            routes_api.create_route(self.context,
                                    dict(route=create_route))
            with self.assertRaises(q_exc.RouteConflict):
                routes_api.create_route(self.context,
                                        dict(route=create_route))
