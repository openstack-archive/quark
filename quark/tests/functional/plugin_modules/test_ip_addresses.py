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

import netaddr

from quark.db import api as db_api
from quark import exceptions as q_exc
from quark.plugin_modules import ip_addresses as ip_addr
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

    @contextlib.contextmanager
    def _stubs(self):
        with self.context.session.begin():
            subnet = db_api.subnet_create(self.context,
                                          cidr="192.168.0.0/24")
            ip = db_api.ip_address_create(self.context,
                                          address=self.addr,
                                          subnet_id=subnet["id"])
        yield subnet, ip

    def test_reserve_ip_non_admin(self):
        ip_address_dealloc = {"ip_address": {"blah": "False"}}
        ip_address_reserve = {"ip_address": {"deallocated": "False"}}
        with self._stubs() as (subnet, ip):
            deallocated_ip = ip_addr.update_ip_address(self.context, ip["id"],
                                                       ip_address_dealloc)
            ip_address = db_api.ip_address_find(
                self.context,
                id=deallocated_ip["id"],
                scope=db_api.ONE)
            self.assertEqual(ip_address["deallocated"], True)
            deallocated_ip = ip_addr.update_ip_address(self.context, ip["id"],
                                                       ip_address_reserve)
            ip_address = db_api.ip_address_find(
                self.context,
                id=deallocated_ip["id"],
                scope=db_api.ONE)
            self.assertEqual(ip_address["deallocated"], True)

    def test_reserve_ip_admin(self):
        self.context.is_admin = True
        ip_address_dealloc = {"ip_address": {"blah": "False"}}
        ip_address_reserve = {"ip_address": {"deallocated": "False"}}
        with self._stubs() as (subnet, ip):
            deallocated_ip = ip_addr.update_ip_address(self.context, ip["id"],
                                                       ip_address_dealloc)
            ip_address = db_api.ip_address_find(
                self.context,
                id=deallocated_ip["id"],
                scope=db_api.ONE)
            self.assertEqual(ip_address["deallocated"], True)
            deallocated_ip = ip_addr.update_ip_address(self.context, ip["id"],
                                                       ip_address_reserve)
            ip_address = db_api.ip_address_find(
                self.context,
                id=deallocated_ip["id"],
                scope=db_api.ONE)
            self.assertEqual(ip_address["deallocated"], False)

    def test_get_single_deallocated_ip_non_admin_raises(self):
        ip_address_dealloc = {"ip_address": {"blah": "False"}}
        with self._stubs() as (subnet, ip):
            reserved_ip = ip_addr.update_ip_address(self.context, ip["id"],
                                                    ip_address_dealloc)
            ip_address = db_api.ip_address_find(
                self.context,
                id=reserved_ip["id"],
                scope=db_api.ONE)
            self.assertEqual(ip_address["deallocated"], True)
            with self.assertRaises(q_exc.IpAddressNotFound):
                ip_addr.get_ip_address(self.context,
                                       ip_address['id'])

    def test_get_deallocated_ips_non_admin_empty(self):
        ip_address_dealloc = {"ip_address": {"blah": "False"}}
        with self._stubs() as (subnet, ip):
            reserved_ip = ip_addr.update_ip_address(self.context, ip["id"],
                                                    ip_address_dealloc)
            ip_address = db_api.ip_address_find(
                self.context,
                id=reserved_ip["id"],
                scope=db_api.ONE)
            self.assertEqual(ip_address["deallocated"], True)
            deallocated_ips = ip_addr.get_ip_addresses(self.context)
            self.assertEqual(len(deallocated_ips), 0)

    def test_get_single_deallocated_ip_admin(self):
        self.context.is_admin = True
        ip_address_dealloc = {"ip_address": {"blah": "False"}}
        with self._stubs() as (subnet, ip):
            reserved_ip = ip_addr.update_ip_address(self.context, ip["id"],
                                                    ip_address_dealloc)
            ip_address = db_api.ip_address_find(
                self.context,
                id=reserved_ip["id"],
                scope=db_api.ONE)
            self.assertEqual(ip_address["deallocated"], True)
            deallocated_ip = ip_addr.get_ip_address(self.context,
                                                    ip_address['id'])
            self.assertEqual(reserved_ip['id'], deallocated_ip['id'])

    def test_get_deallocated_ips_admin(self):
        self.context.is_admin = True
        ip_address_dealloc = {"ip_address": {"blah": "False"}}
        with self._stubs() as (subnet, ip):
            reserved_ip = ip_addr.update_ip_address(self.context, ip["id"],
                                                    ip_address_dealloc)
            ip_address = db_api.ip_address_find(
                self.context,
                id=reserved_ip["id"],
                scope=db_api.ONE)
            self.assertEqual(ip_address["deallocated"], True)
            deallocated_ips = ip_addr.get_ip_addresses(self.context)
            self.assertEqual(len(deallocated_ips), 1)
            self.assertEqual(reserved_ip['id'], deallocated_ips[0]['id'])
