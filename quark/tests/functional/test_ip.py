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

import netaddr

from quark.db import api as db_api
import quark.ipam
import quark.plugin
from quark.tests.functional.base import BaseFunctionalTest


class QuarkIpamBaseFunctionalTest(BaseFunctionalTest):
    def setUp(self):
        super(QuarkIpamBaseFunctionalTest, self).setUp()
        self.plugin = quark.plugin.Plugin()


class QuarkTestIPFiltering(QuarkIpamBaseFunctionalTest):

    def setUp(self):
        super(QuarkTestIPFiltering, self).setUp()
        self.network = dict(name="public", tenant_id="fake")
        test_address1 = netaddr.IPAddress("192.168.1.100")
        test_address2 = netaddr.IPAddress("192.168.1.101")
        test_address3 = netaddr.IPAddress("192.168.1.102")
        ipnet = netaddr.IPNetwork("192.168.1.0/24")
        next_ip = ipnet.ipv6().first + 2
        self.subnet = dict(id=1, cidr="192.168.1.0/24",
                           next_auto_assign_ip=next_ip,
                           ip_policy=None, tenant_id="fake")

        self.ip_address1 = dict(address_readable="192.168.1.100",
                                subnet_id=1,
                                network_id=2, version=4,
                                address=test_address1, id=1)
        self.ip_address2 = dict(address_readable="192.168.1.101",
                                subnet_id=1,
                                network_id=2,
                                version=4,
                                address=test_address2,
                                id=2)
        self.ip_address3 = dict(address_readable="192.168.1.102",
                                subnet_id=1,
                                network_id=2,
                                version=4,
                                address=test_address3,
                                id=3)

    @contextlib.contextmanager
    def _stubs(self, network, subnet, ip_address1, ip_address2, ip_address3):
        with self.context.session.begin():
            net_mod = db_api.network_create(self.context, **network)
            subnet["network"] = net_mod
            sub_mod = db_api.subnet_create(self.context, **subnet)
            # set tenant id to "123"
            ip_address1['network_id'] = net_mod.id
            ip_address1['subnet_id'] = sub_mod.id
            self.context.tenant_id = 123
            ip_address1 = db_api.ip_address_create(self.context, **ip_address1)
            # set tenant_id=456
            ip_address2['network_id'] = net_mod.id
            ip_address2['subnet_id'] = sub_mod.id
            self.context.tenant_id = 456
            ip_address2 = db_api.ip_address_create(self.context, **ip_address2)
            # set tenant id = "123" to test the list of IPs
            ip_address3['network_id'] = net_mod.id
            ip_address3['subnet_id'] = sub_mod.id
            self.context.tenant_id = 123
            ip_address3 = db_api.ip_address_create(self.context, **ip_address3)
        yield net_mod
        with self.context.session.begin():
            db_api.subnet_delete(self.context, sub_mod)
            db_api.network_delete(self.context, net_mod)

    def test_basic_ip_filtering_with_tenant_id(self):
        with self._stubs(self.network, self.subnet,
                         self.ip_address1,
                         self.ip_address2, self.ip_address3):
            res = self.plugin.get_ip_addresses(self.context, tenant_id="123")
            self.assertEqual(2, len(res))
            id = int(res[0].get("id"))
            self.assertEqual(self.ip_address1["id"], id)
            res = self.plugin.get_ip_addresses(self.context, tenant_id="456")
            self.assertEqual(1, len(res))
            id = int(res[0].get("id"))
            self.assertEqual(self.ip_address2["id"], id)

    def test_basic_ip_filtering_with_same_tenant_id_with_different_ip(self):
        with self._stubs(self.network, self.subnet,
                         self.ip_address1, self.ip_address2,
                         self.ip_address3):
            res = self.plugin.get_ip_addresses(self.context, tenant_id="123")
            self.assertEqual(2, len(res))
            id1 = int(res[0].get("id"))
            id3 = int(res[1].get("id"))
            self.assertEqual(self.ip_address1["id"], id1)
            self.assertEqual(self.ip_address3["id"], id3)

    def test_basic_ip_filtering_without_tenant_id(self):
        with self._stubs(self.network, self.subnet, self.ip_address1,
                         self.ip_address2, self.ip_address3):
            res = self.plugin.get_ip_addresses(self.context)
            self.assertEqual(2, len(res))

    def test_basic_ip_filtering_with_tenant_id_without_ip(self):
        with self._stubs(self.network, self.subnet,
                         self.ip_address1,
                         self.ip_address2,
                         self.ip_address3):
            res = self.plugin.get_ip_addresses(self.context, tenant_id="1234")
            self.assertEqual(0, len(res))

    def test_basic_ip_filtering_with_used_by_tenant_id(self):
        with self._stubs(self.network, self.subnet, self.ip_address1,
                         self.ip_address2, self.ip_address3):
            res = self.plugin.get_ip_addresses(self.context,
                                               used_by_tenant_id="123")
            self.assertEqual(2, len(res))
            id = int(res[0].get("id"))
            self.assertEqual(self.ip_address1["id"], id)
            res = self.plugin.get_ip_addresses(self.context,
                                               used_by_tenant_id="456")
            self.assertEqual(0, len(res))

    def test_filtering_with_same_used_by_tenant_id_with_different_ip(self):
        with self._stubs(self.network, self.subnet,
                         self.ip_address1, self.ip_address2,
                         self.ip_address3):
            res = self.plugin.get_ip_addresses(self.context,
                                               used_by_tenant_id="123")
            self.assertEqual(2, len(res))
            id1 = int(res[0].get("id"))
            id3 = int(res[1].get("id"))
            self.assertEqual(self.ip_address1["id"], id1)
            self.assertEqual(self.ip_address3["id"], id3)

    def test_basic_ip_filtering_with_used_by_tenant_id_without_ip(self):
        with self._stubs(self.network, self.subnet,
                         self.ip_address1,
                         self.ip_address2,
                         self.ip_address3):
            res = self.plugin.get_ip_addresses(self.context,
                                               used_by_tenant_id="1234")
            self.assertEqual(0, len(res))

    def test_basic_ip_filtering_without_tenant_id_as_admin(self):
        with self._stubs(self.network, self.subnet, self.ip_address1,
                         self.ip_address2, self.ip_address3):
            res = self.plugin.get_ip_addresses(self.context.elevated())
            self.assertEqual(3, len(res))

    def test_basic_ip_filtering_with_used_by_tenant_id_as_admin(self):
        with self._stubs(self.network, self.subnet, self.ip_address1,
                         self.ip_address2, self.ip_address3):
            res = self.plugin.get_ip_addresses(self.context.elevated(),
                                               used_by_tenant_id="123")
            self.assertEqual(2, len(res))
            id = int(res[0].get("id"))
            self.assertEqual(self.ip_address1["id"], id)
            res = self.plugin.get_ip_addresses(self.context.elevated(),
                                               used_by_tenant_id="456")
            self.assertEqual(1, len(res))
