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

import mock
from neutron.common import exceptions as n_exc_ext
from neutron_lib import exceptions as n_exc

from quark import exceptions as q_exc
from quark.plugin_modules import ip_policies as ippol
from quark.tests import test_base
from quark.tests import test_quark_plugin


class TestQuarkGetIpPolicies(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, ip_policy):
        db_mod = "quark.db.api"
        with mock.patch("%s.ip_policy_find" % db_mod) as ip_policy_find:
            ip_policy_find.return_value = ip_policy
            yield

    def test_get_ip_policy_not_found(self):
        with self._stubs(None):
            with self.assertRaises(q_exc.IPPolicyNotFound):
                self.plugin.get_ip_policy(self.context, 1)

    def test_get_ip_policy(self):
        ip_policy = dict(
            id=1,
            tenant_id=1,
            name="foo",
            subnets=[dict(id=1)],
            networks=[dict(id=2)],
            exclude=[dict(cidr="0.0.0.0/32")])
        with self._stubs(ip_policy):
            resp = self.plugin.get_ip_policy(self.context, 1)
            self.assertEqual(len(resp.keys()), 6)
            self.assertEqual(resp["id"], 1)
            self.assertEqual(resp["name"], "foo")
            self.assertEqual(resp["subnet_ids"], [1])
            self.assertEqual(resp["network_ids"], [2])
            self.assertEqual(resp["exclude"], ["0.0.0.0/32"])
            self.assertEqual(resp["tenant_id"], 1)

    def test_get_ip_policies(self):
        ip_policy = dict(
            id=1,
            tenant_id=1,
            name="foo",
            subnets=[dict(id=1)],
            networks=[dict(id=2)],
            exclude=[dict(cidr="0.0.0.0/32")])
        with self._stubs([ip_policy]):
            resp = self.plugin.get_ip_policies(self.context)
            self.assertEqual(len(resp), 1)
            resp = resp[0]
            self.assertEqual(len(resp.keys()), 6)
            self.assertEqual(resp["id"], 1)
            self.assertEqual(resp["subnet_ids"], [1])
            self.assertEqual(resp["network_ids"], [2])
            self.assertEqual(resp["exclude"], ["0.0.0.0/32"])
            self.assertEqual(resp["name"], "foo")
            self.assertEqual(resp["tenant_id"], 1)


class TestQuarkCreateIpPolicies(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, ip_policy, subnets=None, nets=None):
        db_mod = "quark.db.api"
        with contextlib.nested(
            mock.patch("%s.subnet_find" % db_mod),
            mock.patch("%s.network_find" % db_mod),
            mock.patch("%s.ip_policy_create" % db_mod),
            mock.patch("%s.route_find" % db_mod)
        ) as (subnet_find, net_find, ip_policy_create, route_find):
            subnet_find.return_value = subnets if subnets else None
            net_find.return_value = nets if nets else None
            ip_policy_create.return_value = ip_policy
            route_find.return_value = [{"nexthop": "1.2.3.4"}]
            yield ip_policy_create

    def test_create_ip_policy_invalid_body_missing_exclude(self):
        with self._stubs(None):
            with self.assertRaises(n_exc.BadRequest):
                self.plugin.create_ip_policy(self.context, dict(
                    ip_policy=dict()))

    def test_create_ip_policy_with_both_network_and_subnet_ids(self):
        with self._stubs(None):
            with self.assertRaises(n_exc.BadRequest):
                self.plugin.create_ip_policy(self.context, dict(
                    ip_policy=dict(network_ids=[1], subnet_ids=[1])))

    def test_create_ip_policy_invalid_body_missing_netsubnet(self):
        with self._stubs(None):
            with self.assertRaises(n_exc.BadRequest):
                self.plugin.create_ip_policy(self.context, dict(
                    ip_policy=dict(exclude=["1.1.1.1/24"])))

    def test_create_ip_policy_invalid_subnet(self):
        with self._stubs(None):
            with self.assertRaises(n_exc.SubnetNotFound):
                self.plugin.create_ip_policy(self.context, dict(
                    ip_policy=dict(subnet_ids=[1],
                                   exclude=["1.1.1.1/24"])))

    def test_create_ip_policy_invalid_network(self):
        with self._stubs(None):
            with self.assertRaises(n_exc.NetworkNotFound):
                self.plugin.create_ip_policy(self.context, dict(
                    ip_policy=dict(network_ids=[1],
                                   exclude=["1.1.1.1/24"])))

    def test_create_ip_policy_network_ip_policy_already_exists(self):
        with self._stubs(None, nets=[dict(id=1, ip_policy=dict(id=2),
                                          subnets=[dict(id=1,
                                                        cidr="1.1.1.1/16")])]):
            with self.assertRaises(q_exc.IPPolicyAlreadyExists):
                self.plugin.create_ip_policy(self.context, dict(
                    ip_policy=dict(network_ids=[1],
                                   exclude=["1.1.1.1/24"])))

    def test_create_ip_policy_subnet_ip_policy_already_exists(self):
        with self._stubs(None, subnets=[dict(id=1, ip_policy=dict(id=2),
                                             cidr="1.1.1.1/16")]):
            with self.assertRaises(q_exc.IPPolicyAlreadyExists):
                self.plugin.create_ip_policy(self.context, dict(
                    ip_policy=dict(subnet_ids=[1],
                                   exclude=["1.1.1.1/24"])))

    def test_create_ip_policy_network(self):
        ipp = dict(subnet_id=None, network_id=1,
                   exclude=["1.1.1.1/24"])
        with self._stubs(ipp, nets=[dict(id=1, ip_policy=dict(id=2),
                                         subnets=[dict(id=1,
                                                       cidr="1.1.1.1/16")])]):
            with self.assertRaises(q_exc.IPPolicyAlreadyExists):
                self.plugin.create_ip_policy(self.context, dict(
                    ip_policy=dict(network_ids=[ipp["network_id"]],
                                   exclude=ipp["exclude"])))

    def test_create_ip_policy_subnet(self):
        ipp = dict(subnet_id=1, network_id=None,
                   exclude=["1.1.1.1/24"])
        with self._stubs(ipp, subnets=[dict(id=1, ip_policy=dict(id=2),
                                            cidr="1.1.1.1/16")]):
            with self.assertRaises(q_exc.IPPolicyAlreadyExists):
                self.plugin.create_ip_policy(self.context, dict(
                    ip_policy=dict(subnet_ids=[ipp["subnet_id"]],
                                   exclude=ipp["exclude"])))

    def test_create_ip_policy_with_cidr_that_does_not_fit_into_subnet(self):
        ipp = dict(
            subnets=[dict(id=1, version=4, cidr="192.168.1.1/24")],
            networks=[],
            id=1,
            tenant_id=1,
            exclude=["10.10.10.100/32"],
            name="foo")
        with self._stubs(ipp,
                         subnets=[dict(id=1, ip_policy=None,
                                       version=ipp["subnets"][0]["version"],
                                       cidr=ipp["subnets"][0]["cidr"])]):
            with self.assertRaises(n_exc.BadRequest):
                self.plugin.create_ip_policy(self.context, dict(
                    ip_policy=dict(subnet_ids=[1],
                                   exclude=ipp["exclude"])))

    def test_create_ip_policy_with_ipv6_subnet_cidr(self):
        ipp = dict(
            subnets=[dict(id=1, version=6, cidr='::/64')],
            networks=[],
            id=1,
            tenant_id=1,
            exclude=[dict(cidr="::/128")],
            name="foo")
        with self._stubs(ipp,
                         subnets=[dict(id=1, ip_policy=None,
                                       version=ipp["subnets"][0]["version"],
                                       cidr=ipp["subnets"][0]["cidr"])]):
            exclude = [ippc["cidr"] for ippc in ipp["exclude"]]
            resp = self.plugin.create_ip_policy(self.context, dict(
                ip_policy=dict(subnet_ids=[1], exclude=exclude)))
            self.assertEqual(len(resp.keys()), 6)
            self.assertEqual(resp["subnet_ids"], [1])
            self.assertEqual(resp["network_ids"], [])
            # NOTE(jmeridth): below is mocked that way, so it won't get
            # additional default policies in exclude
            # ippol.ensure_default_policy is tested below in this file
            self.assertEqual(resp["exclude"], ["::/128"])
            self.assertEqual(resp["name"], "foo")
            self.assertEqual(resp["tenant_id"], 1)

    def test_create_ip_policy(self):
        ipp = dict(
            subnets=[dict(id=1, cidr='0.0.0.0/16')],
            networks=[],
            id=1,
            tenant_id=1,
            exclude=[dict(cidr="0.0.0.0/24")],
            name="foo")
        with self._stubs(ipp, subnets=[dict(
                id=1, ip_policy=None, cidr=ipp["subnets"][0]["cidr"])]):
            exclude = [ippc["cidr"] for ippc in ipp["exclude"]]
            resp = self.plugin.create_ip_policy(self.context, dict(
                ip_policy=dict(subnet_ids=[1], exclude=exclude)))
            self.assertEqual(len(resp.keys()), 6)
            self.assertEqual(resp["subnet_ids"], [1])
            self.assertEqual(resp["network_ids"], [])
            # NOTE(jmeridth): below is mocked that way, so it won't get
            # additional default policies in exclude
            # ippol.ensure_default_policy is tested below in this file
            self.assertEqual(resp["exclude"], ["0.0.0.0/24"])
            self.assertEqual(resp["name"], "foo")
            self.assertEqual(resp["tenant_id"], 1)

    def test_create_ip_policy_only_called_once_with_multiple_networks(self):
        ipp = dict(
            subnets=[],
            networks=[dict(id=1, subnets=[dict(id=1,
                           ip_policy=None, cidr='0.0.0.0/24')]),
                      dict(id=2, subnets=[dict(id=2,
                           ip_policy=None, cidr='0.0.0.0/24')])],
            id=1,
            tenant_id=1,
            exclude=[dict(cidr="0.0.0.1/32")],
            name="foo")
        with self._stubs(ipp, nets=ipp["networks"]) as (ip_policy_create):
            resp = self.plugin.create_ip_policy(self.context, dict(
                ip_policy=dict(network_ids=[1, 2], exclude=["0.0.0.1/32"])))
            exclude = ['0.0.0.1/32', '0.0.0.0/32', '0.0.0.255/32']
            ip_policy_create.assert_called_once_with(
                self.context, exclude=exclude,
                networks=[{'subnets':
                          [{'cidr': '0.0.0.0/24', 'ip_policy': None,
                            'id': 1}], 'id': 1},
                          {'subnets':
                          [{'cidr': '0.0.0.0/24', 'ip_policy': None,
                            'id': 2}], 'id': 2}])
            self.assertEqual(len(resp.keys()), 6)
            self.assertEqual(resp["subnet_ids"], [])
            self.assertEqual(resp["network_ids"], [1, 2])
            # NOTE(jmeridth): below is mocked that way, so it won't get
            # additional default policies in exclude
            # ippol.ensure_default_policy is tested below in this file
            self.assertEqual(resp["exclude"], ["0.0.0.1/32"])
            self.assertEqual(resp["name"], "foo")
            self.assertEqual(resp["tenant_id"], 1)

    def test_create_ip_policy_only_called_once_with_multiple_subnets(self):
        ipp = dict(
            subnets=[dict(id=3, cidr='0.0.0.0/16'),
                     dict(id=4, cidr='0.0.0.0/16')],
            networks=[],
            id=1,
            tenant_id=1,
            exclude=[dict(cidr="0.0.0.1/32")],
            name="foo")
        with self._stubs(ipp, subnets=ipp["subnets"]) as (ip_policy_create):
            resp = self.plugin.create_ip_policy(self.context, dict(
                ip_policy=dict(subnet_ids=[3, 4], exclude=["0.0.0.1/32"])))
            exclude = ['0.0.0.1/32', '0.0.0.0/32', '0.0.255.255/32']
            ip_policy_create.assert_called_once_with(
                self.context, exclude=exclude,
                subnets=[{'cidr': '0.0.0.0/16', 'id': 3},
                         {'cidr': '0.0.0.0/16', 'id': 4}])
            self.assertEqual(len(resp.keys()), 6)
            self.assertEqual(resp["subnet_ids"], [3, 4])
            self.assertEqual(resp["network_ids"], [])
            # NOTE(jmeridth): below is mocked that way, so it won't get
            # additional default policies in exclude
            # ippol.ensure_default_policy is tested below in this file
            self.assertEqual(resp["exclude"], ["0.0.0.1/32"])
            self.assertEqual(resp["name"], "foo")
            self.assertEqual(resp["tenant_id"], 1)


class TestQuarkUpdateIpPolicies(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, ip_policy, subnets=None, networks=None):
        if not subnets:
            subnets = []
        if not networks:
            networks = []
        db_mod = "quark.db.api"
        with contextlib.nested(
            mock.patch("%s.ip_policy_find" % db_mod),
            mock.patch("%s.subnet_find" % db_mod),
            mock.patch("%s.network_find" % db_mod),
            mock.patch("%s.ip_policy_update" % db_mod),
        ) as (ip_policy_find, subnet_find, network_find, ip_policy_update):
            ip_policy_find.return_value = ip_policy
            subnet_find.return_value = subnets
            network_find.return_value = networks
            yield ip_policy_update

    def test_update_ip_policy_not_found(self):
        with self._stubs(None):
            with self.assertRaises(q_exc.IPPolicyNotFound):
                self.plugin.update_ip_policy(self.context, 1,
                                             dict(ip_policy=None))

    def test_update_ip_policy_with_both_network_and_subnet_ids(self):
        ipp = dict(id=1, subnets=[])
        with self._stubs(ipp):
            with self.assertRaises(n_exc.BadRequest):
                self.plugin.update_ip_policy(self.context, 1, dict(
                    ip_policy=dict(network_ids=[1], subnet_ids=[1])))

    def test_update_ip_policy_subnets_not_found(self):
        ipp = dict(id=1, subnets=[])
        with self._stubs(ipp):
            with self.assertRaises(n_exc.SubnetNotFound):
                self.plugin.update_ip_policy(
                    self.context,
                    1,
                    dict(ip_policy=dict(subnet_ids=[100])))

    def test_update_ip_policy_subnets_already_exists(self):
        ipp = dict(id=1, subnets=[dict()])
        with self._stubs(
            ipp, subnets=[dict(id=1, ip_policy=dict(id=1))]
        ):
            with self.assertRaises(q_exc.IPPolicyAlreadyExists):
                self.plugin.update_ip_policy(
                    self.context,
                    1,
                    dict(ip_policy=dict(subnet_ids=[100])))

    def test_update_ip_policy_subnets(self):
        ipp = dict(id=1, subnets=[dict()],
                   exclude=["0.0.0.0/24"],
                   name="foo", tenant_id=1)
        with self._stubs(
            ipp, subnets=[dict(id=1, ip_policy=None)]
        ) as (ip_policy_update):
            self.plugin.update_ip_policy(
                self.context,
                1,
                dict(ip_policy=dict(subnet_ids=[100])))
            self.assertEqual(ip_policy_update.called, 1)

    def test_update_ip_policy_subnets_empty_exclude(self):
        ipp = dict(id=1, subnets=[dict()],
                   exclude=["0.0.0.40/32"],
                   name="foo", tenant_id=1)
        with self._stubs(
            ipp, subnets=[dict(id=1, cidr="0.0.0.0/16", ip_policy=None)]
        ) as (ip_policy_update):
            self.plugin.update_ip_policy(
                self.context,
                1,
                dict(ip_policy=dict(subnet_ids=[100], exclude=[])))
            ip_policy_update.assert_called_once_with(
                self.context, ipp, subnet_ids=[100], exclude=[
                    "0.0.0.0/32", "0.0.255.255/32"])

    def test_update_ip_policy_subnets_empty_exclude_without_subnet_ids(self):
        ipp = dict(id=1, subnets=[dict(cidr="0.0.0.0/16")],
                   exclude=["0.0.0.40/32"],
                   name="foo", tenant_id=1)
        with self._stubs(ipp) as (ip_policy_update):
            self.plugin.update_ip_policy(
                self.context,
                1,
                dict(ip_policy=dict(exclude=[])))
            ip_policy_update.assert_called_once_with(
                self.context, ipp, exclude=["0.0.0.0/32", "0.0.255.255/32"])

    def test_update_ip_policy_networks_not_found(self):
        ipp = dict(id=1, networks=[])
        with self._stubs(ipp):
            with self.assertRaises(n_exc.NetworkNotFound):
                self.plugin.update_ip_policy(
                    self.context,
                    1,
                    dict(ip_policy=dict(network_ids=[100])))

    def test_update_ip_policy_networks(self):
        ipp = dict(id=1, networks=[dict()],
                   exclude=["0.0.0.0/24"],
                   name="foo", tenant_id=1)
        with self._stubs(
            ipp, networks=[dict(id=1, ip_policy=None)]
        ) as (ip_policy_update):
            self.plugin.update_ip_policy(
                self.context,
                1,
                dict(ip_policy=dict(network_ids=[100])))
            self.assertEqual(ip_policy_update.called, 1)

    def test_update_ip_policy_exclude_v4(self):
        subnets = [dict(id=100, cidr="0.0.0.0/16")]
        ipp = dict(id=1, subnets=subnets,
                   exclude=["0.0.0.0/24"],
                   name="foo", tenant_id=1)
        with self._stubs(ipp, subnets=subnets) as (ip_policy_update):
            self.plugin.update_ip_policy(
                self.context,
                1,
                dict(ip_policy=dict(subnet_ids=[100], exclude=["0.0.0.1/32"])))
            ip_policy_update.assert_called_once_with(
                self.context,
                ipp,
                subnet_ids=[100],
                exclude=["0.0.0.1/32", "0.0.0.0/32", "0.0.255.255/32"])

    def test_update_ip_policy_exclude_v6(self):
        subnets = [dict(id=100, cidr="::/64")]
        ipp = dict(id=1, subnets=subnets,
                   exclude=["::/128"],
                   name="foo", tenant_id=1)
        with self._stubs(ipp, subnets=subnets) as (ip_policy_update):
            self.plugin.update_ip_policy(
                self.context,
                1,
                dict(ip_policy=dict(subnet_ids=[100], exclude=["::1/128"])))
            ip_policy_update.assert_called_once_with(
                self.context,
                ipp,
                subnet_ids=[100],
                exclude=["::1/128", "::/128", "::ffff:ffff:ffff:ffff/128"])


class TestQuarkDeleteIpPolicies(test_quark_plugin.TestQuarkPlugin):
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
            with self.assertRaises(q_exc.IPPolicyNotFound):
                self.plugin.delete_ip_policy(self.context, 1)

    def test_delete_ip_policy_in_use(self):
        with self._stubs(dict(networks=True)):
            with self.assertRaises(q_exc.IPPolicyInUse):
                self.plugin.delete_ip_policy(self.context, 1)

    def test_delete_ip_policy(self):
        ip_policy = dict(
            id=1,
            networks=[],
            subnets=[])
        with self._stubs(ip_policy) as (ip_policy_find, ip_policy_delete):
            self.plugin.delete_ip_policy(self.context, 1)
            self.assertEqual(ip_policy_find.call_count, 1)
            self.assertEqual(ip_policy_delete.call_count, 1)


class TestQuarkUpdatePolicySubnetWithRoutes(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, ip_policy, subnets=None, routes=None):
        subnets = subnets or []
        db_mod = "quark.db.api"
        with contextlib.nested(
            mock.patch("%s.ip_policy_find" % db_mod),
            mock.patch("%s.subnet_find" % db_mod),
            mock.patch("%s.route_find" % db_mod),
            mock.patch("%s.ip_policy_update" % db_mod),
        ) as (ip_policy_find, subnet_find, route_find, ip_policy_update):
            ip_policy_find.return_value = ip_policy
            subnet_find.return_value = subnets
            route_find.return_value = routes
            yield ip_policy_update

    def test_update_ip_policy_has_route_conflict_raises(self):
        subnet = dict(id=1, cidr="192.168.0.0/24")
        ipp = dict(id=1, subnets=[subnet], exclude=["192.168.0.1/32"],
                   name="foo", tenant_id=1)
        route = {"gateway": "192.168.0.1", "subnet_id": subnet["id"]}
        with self._stubs(ipp, subnets=[subnet], routes=[route]):
            with self.assertRaises(
                    n_exc_ext.GatewayConflictWithAllocationPools):
                self.plugin.update_ip_policy(
                    self.context, 1,
                    dict(ip_policy=dict(subnet_ids=[1], exclude=[])))

    def test_update_ip_policy_no_route_conflict(self):
        subnet = dict(id=1, cidr="192.168.0.0/24")
        ipp = dict(id=1, subnets=[subnet], exclude=["192.168.0.1/32"],
                   name="foo", tenant_id=1)
        route = {"gateway": "192.168.0.1", "subnet_id": subnet["id"]}
        with self._stubs(ipp, subnets=[subnet], routes=[route]):
            try:
                self.plugin.update_ip_policy(
                    self.context, 1,
                    dict(ip_policy=dict(subnet_ids=[1],
                                        exclude=["192.168.0.0/24"])))
            except Exception as e:
                self.fail("This shouldn't have raised: %s" % e)


class TestQuarkValidateCIDRsFitsIntoSubnets(test_quark_plugin.TestQuarkPlugin):
    def test_normal_cidr_and_valid_subnet(self):
        try:
            ippol._validate_cidrs_fit_into_subnets(
                ["192.168.0.100/32"],
                [dict(id=1, cidr="192.168.0.0/24")])
        except Exception:
            self.fail("Should not have failed")

    def test_normal_ipv4_cidr_and_valid_ipv6_subnet(self):
        try:
            ippol._validate_cidrs_fit_into_subnets(
                ["192.168.0.100/32"], [dict(id=1, cidr="::/96")])
        except Exception:
            self.fail("Should not have failed")

    def test_normal_ipv6_cidr_and_valid_ipv6_subnet(self):
        try:
            ippol._validate_cidrs_fit_into_subnets(
                ["::/128"], [dict(id=1, cidr="::/96")])
        except Exception:
            self.fail("Should not have failed")

    def test_normal_ipv6_cidr_and_valid_ipv4_subnet(self):
        try:
            ippol._validate_cidrs_fit_into_subnets(
                ["::/128"], [dict(id=1, cidr="192.168.0.0/24")])
        except Exception:
            self.fail("Should not have failed")

    def test_normal_cidr_and_multiple_valid_subnet(self):
        try:
            ippol._validate_cidrs_fit_into_subnets(
                ["192.168.0.100/32"],
                [dict(id=1, cidr="192.168.0.0/24"),
                 dict(id=2, cidr="192.168.0.0/16")])
        except Exception:
            self.fail("Should not have failed")

    def test_normal_ipv6_cidr_and_multiple_valid_ipv6_subnet(self):
        try:
            ippol._validate_cidrs_fit_into_subnets(
                ["::/128"],
                [dict(id=1, cidr="::/96"),
                 dict(id=2, cidr="::/64")])
        except Exception:
            self.fail("Should not have failed")

    def test_normal_cidr_and_invalid_subnet(self):
        with self.assertRaises(n_exc.BadRequest):
            ippol._validate_cidrs_fit_into_subnets(
                ["192.168.0.100/32"],
                [dict(id=1, cidr="10.10.10.0/24")])

    def test_normal_ipv6_cidr_and_invalid_ipv6_subnet(self):
        with self.assertRaises(n_exc.BadRequest):
            ippol._validate_cidrs_fit_into_subnets(
                ["::/64"], [dict(id=1, cidr="::/96")])

    def test_normal_cidr_and_one_invalid_and_one_valid_subnet(self):
        with self.assertRaises(n_exc.BadRequest):
            ippol._validate_cidrs_fit_into_subnets(
                ["192.168.0.100/32"],
                [dict(id=1, cidr="10.10.10.0/24"),
                 dict(id=1, cidr="192.168.0.0/24")])

    def test_normal_ipv6_cidr_and_one_invalid_and_one_valid_ipv6_subnet(self):
        with self.assertRaises(n_exc.BadRequest):
            ippol._validate_cidrs_fit_into_subnets(
                ["::/127"],
                [dict(id=1, cidr="::/96"),
                 dict(id=1, cidr="::/128")])


class TestQuarkEnsureDefaultPolicy(test_base.TestBase):
    def test_no_cidrs_no_subnets(self):
        cidrs = []
        subnets = []
        self.assertIsNone(ippol.ensure_default_policy(cidrs, subnets))
        self.assertEqual(cidrs, [])
        self.assertEqual(subnets, [])

    def test_no_cidrs_v4(self):
        cidrs = []
        subnets = [dict(cidr="192.168.10.1/24")]
        self.assertIsNone(ippol.ensure_default_policy(cidrs, subnets))
        self.assertEqual(cidrs, ["192.168.10.0/32", "192.168.10.255/32"])
        self.assertEqual(subnets, [dict(cidr="192.168.10.1/24")])

    def test_no_subnets_v4(self):
        cidrs = ["192.168.10.0/32", "192.168.10.255/32"]
        subnets = []
        self.assertIsNone(ippol.ensure_default_policy(cidrs, subnets))
        self.assertEqual(cidrs, ["192.168.10.0/32", "192.168.10.255/32"])
        self.assertEqual(subnets, [])

    def test_cidrs_without_default_cidrs_v4(self):
        cidrs = ["192.168.10.20/32", "192.168.10.40/32"]
        subnets = [dict(cidr="192.168.10.1/24")]
        self.assertIsNone(ippol.ensure_default_policy(cidrs, subnets))
        self.assertEqual(cidrs, ["192.168.10.20/32", "192.168.10.40/32",
                                 "192.168.10.0/32", "192.168.10.255/32"])
        self.assertEqual(subnets, [dict(cidr="192.168.10.1/24")])

    def test_cidrs_with_default_cidrs_v4(self):
        cidrs = ["192.168.10.0/32", "192.168.10.255/32"]
        subnets = [dict(cidr="192.168.10.1/24")]
        self.assertIsNone(ippol.ensure_default_policy(cidrs, subnets))
        self.assertEqual(cidrs, ["192.168.10.0/32", "192.168.10.255/32"])
        self.assertEqual(subnets, [dict(cidr="192.168.10.1/24")])

    def test_no_cidrs_v6(self):
        cidrs = []
        subnets = [dict(cidr="::/64")]
        self.assertIsNone(ippol.ensure_default_policy(cidrs, subnets))
        self.assertEqual(cidrs, ["::/128", "::ffff:ffff:ffff:ffff/128"])
        self.assertEqual(subnets, [dict(cidr="::/64")])

    def test_no_subnets_v6(self):
        cidrs = ["::/128", "::ffff:ffff:ffff:ffff/128"]
        subnets = []
        self.assertIsNone(ippol.ensure_default_policy(cidrs, subnets))
        self.assertEqual(cidrs, ["::/128", "::ffff:ffff:ffff:ffff/128"])
        self.assertEqual(subnets, [])

    def test_cidrs_without_default_cidrs_v6(self):
        cidrs = ["::10/128", "::20/128"]
        subnets = [dict(cidr="::/64")]
        self.assertIsNone(ippol.ensure_default_policy(cidrs, subnets))
        self.assertEqual(cidrs, ["::10/128", "::20/128",
                                 "::/128", "::ffff:ffff:ffff:ffff/128"])
        self.assertEqual(subnets, [dict(cidr="::/64")])

    def test_cidrs_with_default_cidrs_v6(self):
        cidrs = ["::/128", "::ffff:ffff:ffff:ffff/128"]
        subnets = [dict(cidr="::/64")]
        self.assertIsNone(ippol.ensure_default_policy(cidrs, subnets))
        self.assertEqual(cidrs, ["::/128", "::ffff:ffff:ffff:ffff/128"])
        self.assertEqual(subnets, [dict(cidr="::/64")])

    def test_no_duplicates_in_result_when_called_twice(self):
        cidrs = ["192.168.10.10/32"]
        subnets = [dict(cidr="192.168.10.0/24")]
        self.assertIsNone(ippol.ensure_default_policy(cidrs, subnets))
        self.assertEqual(cidrs, ["192.168.10.10/32", "192.168.10.0/32",
                                 "192.168.10.255/32"])
        cidrs2 = ["192.168.10.10/32"]
        self.assertIsNone(ippol.ensure_default_policy(cidrs2, subnets))
        self.assertEqual(cidrs, ["192.168.10.10/32", "192.168.10.0/32",
                                 "192.168.10.255/32"])
        self.assertEqual(subnets, [dict(cidr="192.168.10.0/24")])
