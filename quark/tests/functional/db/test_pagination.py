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

from quark.db import api as db_api
import quark.ipam
import quark.plugin
import quark.plugin_modules.mac_address_ranges as macrng_api
import quark.plugin_modules.networks as network_api
import quark.plugin_modules.ports as port_api
import quark.plugin_modules.subnets as subnet_api
from quark.tests.functional.base import BaseFunctionalTest


class QuarkNetworksPaginationFunctionalTest(BaseFunctionalTest):
    def test_networks_pagination(self):
        networks_per_page = 1
        networkA = dict(name="fake_A", tenant_id="fake", network_plugin="BASE")
        networkB = dict(name="fake_B", tenant_id="fake", network_plugin="BASE")
        db_api.network_create(self.context, **networkA)
        db_api.network_create(self.context, **networkB)
        res = network_api.get_networks(self.context, networks_per_page,
                                       [('id', 'asc')], None, False,
                                       None)
        self.assertEqual(len(res), networks_per_page)
        res = network_api.get_networks(self.context)
        self.assertNotEqual(len(res), networks_per_page)


class QuarkSubnetsPaginationFunctionalTest(BaseFunctionalTest):
    @contextlib.contextmanager
    def _stubs(self, network, subnets):
        self.ipam = quark.ipam.QuarkIpamANY()
        with self.context.session.begin():
            net_mod = db_api.network_create(self.context, **network)
            for subnet in subnets:
                subnet["network"] = net_mod
                db_api.subnet_create(self.context, **subnet)
        yield net_mod

    def test_subnet_pagination(self):
        subnets_per_page = 1
        network = dict(name="public", tenant_id="fake")
        ipnet = netaddr.IPNetwork("0.0.0.0/24")
        next_ip = ipnet.ipv6().first + 1
        subnet_1 = dict(id=1, cidr="0.0.0.0/24", next_auto_assign_ip=next_ip,
                        ip_policy=None, tenant_id="fake")
        subnet_2 = dict(id=2, cidr="1.1.1.0/24", next_auto_assign_ip=next_ip,
                        ip_policy=None, tenant_id="fake")
        with self._stubs(network, [subnet_1, subnet_2]):
            subnets_unpaged = subnet_api.get_subnets(self.context, filters={})
            subnets_paged = subnet_api.get_subnets(self.context,
                                                   subnets_per_page, False,
                                                   [('id', 'asc')],
                                                   filters={})
            self.assertEqual(len(subnets_paged), subnets_per_page)
            self.assertNotEqual(len(subnets_unpaged), subnets_per_page)


class QuarkPortsPaginationFunctionalTest(BaseFunctionalTest):
    @contextlib.contextmanager
    def _stubs(self, network_info, subnet_info):
        with contextlib.nested(
                mock.patch("neutron.common.rpc.get_notifier"),
                mock.patch("neutron.quota.QUOTAS.limit_check")):
            self.context.is_admin = True
            net = network_api.create_network(self.context, network_info)
            mac = {'mac_address_range': dict(cidr="AA:BB:CC")}
            macrng_api.create_mac_address_range(self.context, mac)
            self.context.is_admin = False
            sub_ports = []
            subnet_info['subnet']['network_id'] = net['id']
            sub_ports.append(subnet_api.create_subnet(self.context,
                                                      subnet_info))
            yield net, sub_ports

    def test_ports_pagination(self):
        cidr = "192.168.1.0/24"

        ip_network = netaddr.IPNetwork(cidr)

        network = dict(id="1", name="public", tenant_id="make",
                       network_plugin="BASE",
                       ipam_strategy="ANY")
        network = {"network": network}

        subnet = dict(id="1", ip_version=4, next_auto_assign_ip=2,
                      cidr=cidr, first_ip=ip_network.first,
                      last_ip=ip_network.last, ip_policy=None,
                      tenant_id="fake")
        subnet_info = {"subnet": subnet}

        def _make_body():
            fix_ipv4 = dict(subnet_id=sub_ports[0]['id'])
            port_info = {"port": dict(fixed_ips=[fix_ipv4],
                                      network_id=net['id'])}
            return port_info

        ports_per_page = 1
        with self._stubs(network, subnet_info) as (
                net, sub_ports):
            port_api.create_port(self.context, _make_body())
            port_api.create_port(self.context, _make_body())
            res_ports = port_api.get_ports(self.context, ports_per_page,
                                           [('id', 'asc')], None)
            self.assertEqual(len(res_ports), ports_per_page)
            res_ports = port_api.get_ports(self.context)
            self.assertNotEqual(len(res_ports), ports_per_page)
            # Note (Perkins): Testing for a default sort on created_at,
            # but created_at is not available, so check that mac addresses,
            # which are created sequentially, are ordered correctly.
            res_ports = port_api.get_ports(self.context, 2, None, None)
            self.assertTrue(res_ports[0]['mac_address'] <
                            res_ports[1]['mac_address'])
