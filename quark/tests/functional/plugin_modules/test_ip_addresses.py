# Copyright 2014 Rackspace Hosting Inc.
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
import netaddr
from neutron_lib import exceptions as n_exc

from oslo_config import cfg

from quark.db import api as db_api
from quark import exceptions as q_exc
from quark.plugin_modules import ip_addresses as ip_addr
import quark.plugin_modules.mac_address_ranges as macrng_api
import quark.plugin_modules.networks as network_api
import quark.plugin_modules.ports as port_api
from quark.tests.functional.base import BaseFunctionalTest


class QuarkGetIPAddresses(BaseFunctionalTest):
    def setUp(self):
        super(QuarkGetIPAddresses, self).setUp()
        self.addr = netaddr.IPAddress("192.168.10.1")

    @contextlib.contextmanager
    def _stubs(self):
        with self.context.session.begin():
            subnet = db_api.subnet_create(self.context,
                                          cidr="192.168.0.0/24")
            db_api.ip_address_create(self.context,
                                     address=self.addr,
                                     subnet_id=subnet["id"])
        yield

    def test_ip_address_find_ip_address_object_filter(self):
        with self._stubs():
            ip_addresses = db_api.ip_address_find(
                self.context,
                ip_address=self.addr,
                scope=db_api.ALL)
            self.assertEqual(len(ip_addresses), 1)
            self.assertEqual(ip_addresses[0]["address"],
                             self.addr.ipv6().value)

    def test_ip_address_find_ip_address_object_filter_none(self):
        with self._stubs():
            ip_addresses = db_api.ip_address_find(
                self.context,
                ip_address=netaddr.IPAddress("192.168.10.2"),
                scope=db_api.ALL)
            self.assertEqual(len(ip_addresses), 0)

    def test_ip_address_find_ip_address_list_filter(self):
        with self._stubs():
            ip_addresses = db_api.ip_address_find(
                self.context,
                ip_address=[self.addr],
                scope=db_api.ALL)
            self.assertEqual(len(ip_addresses), 1)
            self.assertEqual(ip_addresses[0]["address"],
                             self.addr.ipv6().value)

    def test_ip_address_find_ip_address_object_list_none(self):
        with self._stubs():
            ip_addresses = db_api.ip_address_find(
                self.context,
                ip_address=[netaddr.IPAddress("192.168.10.2")],
                scope=db_api.ALL)
            self.assertEqual(len(ip_addresses), 0)


class QuarkTestReserveIPAdmin(BaseFunctionalTest):
    def setUp(self):
        super(QuarkTestReserveIPAdmin, self).setUp()
        self.addr = netaddr.IPAddress("192.168.10.1")
        self.ip_address_dealloc = {"ip_address": {"blah": "False"}}
        self.ip_address_reserve = {"ip_address": {"deallocated": "False"}}

    @contextlib.contextmanager
    def _stubs(self):
        with self.context.session.begin():
            subnet = db_api.subnet_create(self.context,
                                          cidr="192.168.0.0/24")
            ip = db_api.ip_address_create(self.context,
                                          address=self.addr,
                                          subnet_id=subnet["id"])
        yield ip

    def test_reserve_ip_non_admin(self):
        with self._stubs() as ip:
            deallocated_ip = ip_addr.update_ip_address(self.context, ip["id"],
                                                       self.ip_address_dealloc)
            ip_address = db_api.ip_address_find(
                self.context,
                id=deallocated_ip["id"],
                scope=db_api.ONE)
            self.assertEqual(ip_address["deallocated"], True)
            deallocated_ip = ip_addr.update_ip_address(self.context, ip["id"],
                                                       self.ip_address_reserve)
            ip_address = db_api.ip_address_find(
                self.context,
                id=deallocated_ip["id"],
                scope=db_api.ONE)
            self.assertEqual(ip_address["deallocated"], True)

    def test_reserve_ip_admin(self):
        self.context.is_admin = True
        with self._stubs() as ip:
            deallocated_ip = ip_addr.update_ip_address(self.context, ip["id"],
                                                       self.ip_address_dealloc)
            ip_address = db_api.ip_address_find(
                self.context,
                id=deallocated_ip["id"],
                scope=db_api.ONE)
            self.assertEqual(ip_address["deallocated"], True)
            deallocated_ip = ip_addr.update_ip_address(self.context, ip["id"],
                                                       self.ip_address_reserve)
            ip_address = db_api.ip_address_find(
                self.context,
                id=deallocated_ip["id"],
                scope=db_api.ONE)
            self.assertEqual(ip_address["deallocated"], False)


class QuarkTestReserveIPAdminWithPorts(BaseFunctionalTest):
    def setUp(self):
        super(QuarkTestReserveIPAdminWithPorts, self).setUp()
        self.addr = netaddr.IPAddress("192.168.10.1")
        self.ip_address_dealloc = {"ip_address": {"deallocated": "True"}}

    @contextlib.contextmanager
    def _stubs(self):
        with mock.patch("neutron.common.rpc.get_notifier"), \
                mock.patch("neutron.quota.QUOTAS.limit_check"):
            mac = {'mac_address_range': dict(cidr="AA:BB:CC")}
            self.context.is_admin = True
            macrng_api.create_mac_address_range(self.context, mac)
            self.context.is_admin = False
            network_info = dict(name="public", tenant_id="fake",
                                network_plugin="BASE",
                                ipam_strategy="ANY")
            network_info = {"network": network_info}
            network = network_api.create_network(self.context, network_info)
            subnet = db_api.subnet_create(self.context, tenant_id="fake",
                                          cidr="192.168.10.0/24",
                                          network_id=network['id'])

            fixed_ips = [dict(subnet_id=subnet['id'], enabled=True,
                         ip_address=self.addr)]
            port = dict(port=dict(network_id=network['id'],
                                  tenant_id=self.context.tenant_id,
                                  device_id=2,
                                  fixed_ips=fixed_ips))
            port_api.create_port(self.context, port)
            self.context.is_admin = True
            filters = {"deallocated": "both"}
            ip = ip_addr.get_ip_addresses(self.context, **filters)
            self.context.is_admin = False
        yield ip[0]

    def test_reserve_ip_admin_port_assoc_raises_not_authorized(self):
        # This value prevents the testing of the exception thrown if an admin
        # attempts to deallocate/allocate an IP associated with a port since
        # an exception is thrown beforehand.
        old_override = cfg.CONF.QUARK.ipaddr_allow_fixed_ip
        cfg.CONF.set_override('ipaddr_allow_fixed_ip', True, 'QUARK')
        with self._stubs() as ip:
            with self.assertRaises(q_exc.ActionNotAuthorized):
                self.context.is_admin = True
                ip_addr.update_ip_address(self.context, ip["id"],
                                          self.ip_address_dealloc)

        cfg.CONF.set_override('ipaddr_allow_fixed_ip', old_override, 'QUARK')

    def test_reserve_ip_admin_port_assoc_raises_bad_request(self):
        with self._stubs() as ip:
            with self.assertRaises(n_exc.BadRequest):
                self.context.is_admin = True
                ip_addr.update_ip_address(self.context, ip["id"],
                                          self.ip_address_dealloc)

    def test_reserve_ip_non_admin_port_assoc_raises_bad_request(self):
        with self._stubs() as ip:
            with self.assertRaises(n_exc.BadRequest):
                ip_addr.update_ip_address(self.context, ip["id"],
                                          self.ip_address_dealloc)


class QuarkTestGetDeallocatedIP(BaseFunctionalTest):
    def setUp(self):
        super(QuarkTestGetDeallocatedIP, self).setUp()
        self.addr = netaddr.IPAddress("192.168.10.1")
        self.ip_address_dealloc = {"ip_address": {"this": "deallocates"}}

    @contextlib.contextmanager
    def _stubs(self):
        with self.context.session.begin():
            subnet = db_api.subnet_create(self.context,
                                          cidr="192.168.0.0/24")
            ip = db_api.ip_address_create(self.context,
                                          address=self.addr,
                                          subnet_id=subnet["id"])
        yield ip

    def test_get_single_deallocated_ip_non_admin_raises(self):
        with self._stubs() as ip:
            reserved_ip = ip_addr.update_ip_address(self.context, ip["id"],
                                                    self.ip_address_dealloc)
            ip_address = db_api.ip_address_find(
                self.context,
                id=reserved_ip["id"],
                scope=db_api.ONE)
            self.assertEqual(ip_address["deallocated"], True)
            with self.assertRaises(q_exc.IpAddressNotFound):
                ip_addr.get_ip_address(self.context,
                                       ip_address['id'])

    def test_get_deallocated_ips_non_admin_empty(self):
        with self._stubs() as ip:
            reserved_ip = ip_addr.update_ip_address(self.context, ip["id"],
                                                    self.ip_address_dealloc)
            ip_address = db_api.ip_address_find(
                self.context,
                id=reserved_ip["id"],
                scope=db_api.ONE)
            self.assertEqual(ip_address["deallocated"], True)
            deallocated_ips = ip_addr.get_ip_addresses(self.context)
            self.assertEqual(len(deallocated_ips), 0)

    def test_get_single_deallocated_ip_admin(self):
        self.context.is_admin = True
        with self._stubs() as ip:
            reserved_ip = ip_addr.update_ip_address(self.context, ip["id"],
                                                    self.ip_address_dealloc)
            ip_address = db_api.ip_address_find(
                self.context,
                id=reserved_ip["id"],
                scope=db_api.ONE)
            self.assertEqual(ip_address["deallocated"], True)
            deallocated_ip = ip_addr.get_ip_address(self.context,
                                                    ip_address['id'])
            self.assertEqual(reserved_ip['id'], deallocated_ip['id'])
            self.assertEqual(deallocated_ip['_deallocated'], True)

    def test_get_deallocated_ips_admin(self):
        self.context.is_admin = True
        with self._stubs() as ip:
            reserved_ip = ip_addr.update_ip_address(self.context, ip["id"],
                                                    self.ip_address_dealloc)
            ip_address = db_api.ip_address_find(
                self.context,
                id=reserved_ip["id"],
                scope=db_api.ONE)
            self.assertEqual(ip_address["deallocated"], True)
            filters = {'deallocated': 'True'}
            deallocated_ips = ip_addr.get_ip_addresses(self.context, **filters)
            self.assertEqual(len(deallocated_ips), 1)
            self.assertEqual(reserved_ip['id'], deallocated_ips[0]['id'])
            self.assertEqual(deallocated_ips[0]['_deallocated'], True)


class QuarkTestGetMultipleDeallocatedIPs(BaseFunctionalTest):
    def setUp(self):
        super(QuarkTestGetMultipleDeallocatedIPs, self).setUp()
        self.addr1 = netaddr.IPAddress("192.168.10.1")
        self.addr2 = netaddr.IPAddress("192.168.10.2")
        self.ip_address_dealloc = {"ip_address": {"this": "deallocates"}}

    @contextlib.contextmanager
    def _stubs(self):
        with self.context.session.begin():
            subnet = db_api.subnet_create(self.context,
                                          cidr="192.168.0.0/24")
            ip1 = db_api.ip_address_create(self.context,
                                           address=self.addr1,
                                           subnet_id=subnet["id"])
            ip2 = db_api.ip_address_create(self.context,
                                           address=self.addr2,
                                           subnet_id=subnet["id"])
        yield ip1, ip2

    def test_get_deallocated_ips_admin_both(self):
        self.context.is_admin = True
        with self._stubs() as (ip1, ip2):
            reserved_ip = ip_addr.update_ip_address(self.context, ip2["id"],
                                                    self.ip_address_dealloc)
            self.assertEqual(reserved_ip["_deallocated"], True)

            deallocated_ips = ip_addr.get_ip_addresses(self.context)
            self.assertEqual(len(deallocated_ips), 1)
            self.assertEqual(ip1['id'], deallocated_ips[0]['id'])
            self.assertEqual(deallocated_ips[0]['_deallocated'], False)

            filters = {'deallocated': 'True'}
            deallocated_ips = ip_addr.get_ip_addresses(self.context, **filters)
            self.assertEqual(len(deallocated_ips), 1)
            self.assertEqual(reserved_ip['id'], deallocated_ips[0]['id'])
            self.assertEqual(deallocated_ips[0]['_deallocated'], True)

            filters = {'deallocated': 'False'}
            deallocated_ips = ip_addr.get_ip_addresses(self.context, **filters)
            self.assertEqual(len(deallocated_ips), 1)
            self.assertEqual(ip1['id'], deallocated_ips[0]['id'])
            self.assertEqual(deallocated_ips[0]['_deallocated'], False)

            filters = {'deallocated': 'both'}
            deallocated_ips = ip_addr.get_ip_addresses(self.context, **filters)
            self.assertEqual(len(deallocated_ips), 2)
            for ip in deallocated_ips:
                if ip["id"] == ip1["id"]:
                    self.assertEqual(ip["_deallocated"], False)
                elif ip["id"] == ip2["id"]:
                    self.assertEqual(ip["_deallocated"], True)

    def test_get_deallocated_ips_non_admin_both(self):
        with self._stubs() as (ip1, ip2):
            reserved_ip = ip_addr.update_ip_address(self.context, ip2["id"],
                                                    self.ip_address_dealloc)
            self.assertNotIn('_deallocated', reserved_ip)

            ip_addresses = db_api.ip_address_find(
                self.context,
                scope=db_api.ALL)
            self.assertEqual(len(ip_addresses), 2)
            for ip in ip_addresses:
                if ip["id"] == ip1["id"]:
                    self.assertEqual(ip["_deallocated"], False)
                elif ip["id"] == ip2["id"]:
                    self.assertEqual(ip["_deallocated"], True)

            deallocated_ips = ip_addr.get_ip_addresses(self.context)
            self.assertEqual(len(deallocated_ips), 1)
            self.assertEqual(ip1['id'], deallocated_ips[0]['id'])
            self.assertNotIn('_deallocated', deallocated_ips[0])

            filters = {'deallocated': 'True'}
            deallocated_ips1 = ip_addr.get_ip_addresses(self.context,
                                                        **filters)
            self.assertEqual(len(deallocated_ips1), 1)

            filters = {'deallocated': 'False'}
            deallocated_ips1 = ip_addr.get_ip_addresses(self.context,
                                                        **filters)
            self.assertEqual(len(deallocated_ips1), 1)

            filters = {'deallocated': 'both'}
            deallocated_ips = ip_addr.get_ip_addresses(self.context, **filters)
            self.assertEqual(len(deallocated_ips), 1)
            self.assertEqual(ip1['id'], deallocated_ips[0]['id'])
            self.assertNotIn('_deallocated', deallocated_ips[0])
