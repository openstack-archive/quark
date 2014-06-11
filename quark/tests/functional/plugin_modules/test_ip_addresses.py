# Copyright 2014 Openstack Foundation
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
import unittest2
from neutron import context
from neutron.db import api as neutron_db_api
from oslo.config import cfg

from quark.db import api as db_api
from quark.db import models


class QuarkIPAddressFunctionalTest(unittest2.TestCase):
    def setUp(self):
        self.context = context.Context('fake', 'fake', is_admin=False)
        super(QuarkIPAddressFunctionalTest, self).setUp()

        cfg.CONF.set_override('connection', 'sqlite://', 'database')
        neutron_db_api.configure_db()
        neutron_db_api.register_models(models.BASEV2)

    def tearDown(self):
        neutron_db_api.unregister_models(models.BASEV2)
        neutron_db_api.clear_db()


class QuarkGetIPAddresses(QuarkIPAddressFunctionalTest):
    def setUp(self):
        super(QuarkGetIPAddresses, self).setUp()
        self.addr = netaddr.IPAddress("192.168.10.1")

    @contextlib.contextmanager
    def _stubs(self):
        with self.context.session.begin():
            db_api.ip_address_create(self.context,
                                     address=self.addr)
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
