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
import datetime

import mock
import netaddr
from neutron.common import exceptions
from neutron.common import rpc
from neutron import context
from neutron.db import api as neutron_db_api
from neutron.openstack.common import timeutils
from oslo.config import cfg
import unittest2

from quark.db import api as db_api
from quark.db import models
import quark.ipam


class QuarkIpamBaseFunctionalTest(unittest2.TestCase):
    def setUp(self):
        self.context = context.Context('fake', 'fake', is_admin=False)
        super(QuarkIpamBaseFunctionalTest, self).setUp()

        patcher = mock.patch("neutron.common.rpc.messaging")
        patcher.start()
        self.addCleanup(patcher.stop)
        rpc.init(mock.MagicMock())

        cfg.CONF.set_override('connection', 'sqlite://', 'database')
        neutron_db_api.configure_db()
        neutron_db_api.register_models(models.BASEV2)

    def tearDown(self):
        neutron_db_api.unregister_models(models.BASEV2)
        neutron_db_api.clear_db()


class QuarkIPAddressAllocate(QuarkIpamBaseFunctionalTest):
    @contextlib.contextmanager
    def _stubs(self, network, subnet):
        self.ipam = quark.ipam.QuarkIpamANY()
        with self.context.session.begin():
            next_ip = subnet.pop("next_auto_assign_ip", 0)
            net_mod = db_api.network_create(self.context, **network)
            subnet["network"] = net_mod
            sub_mod = db_api.subnet_create(self.context, **subnet)
            # NOTE(asadoughi): update after cidr constructor has been invoked
            db_api.subnet_update(self.context,
                                 sub_mod,
                                 next_auto_assign_ip=next_ip)
        yield net_mod
        with self.context.session.begin():
            db_api.subnet_delete(self.context, sub_mod)
            db_api.network_delete(self.context, net_mod)

    def test_allocate_finds_no_deallocated_creates_new_ip(self):
        network = dict(name="public", tenant_id="fake")
        ipnet = netaddr.IPNetwork("0.0.0.0/24")
        next_ip = ipnet.ipv6().first + 2
        subnet = dict(id=1, cidr="0.0.0.0/24", next_auto_assign_ip=next_ip,
                      ip_policy=None, tenant_id="fake")
        with self._stubs(network, subnet) as net:
            ipaddress = []
            self.ipam.allocate_ip_address(self.context, ipaddress,
                                          net["id"], 0, 0)
            self.assertIsNotNone(ipaddress[0]['id'])
            self.assertEqual(ipaddress[0]['address'], 281470681743362)
            self.assertEqual(ipaddress[0]['version'], 4)
            self.assertEqual(ipaddress[0]['used_by_tenant_id'], "fake")


class QuarkIPAddressReallocate(QuarkIpamBaseFunctionalTest):
    @contextlib.contextmanager
    def _stubs(self, network, subnet, address):
        self.ipam = quark.ipam.QuarkIpamANY()
        with self.context.session.begin():
            next_ip = subnet.pop("next_auto_assign_ip", 0)
            net_mod = db_api.network_create(self.context, **network)
            subnet["network"] = net_mod
            sub_mod = db_api.subnet_create(self.context, **subnet)

            address["network_id"] = net_mod["id"]
            address["subnet_id"] = sub_mod["id"]
            ip = db_api.ip_address_create(self.context, **address)
            address.pop("address")
            db_api.ip_address_update(self.context, ip, **address)

            # NOTE(asadoughi): update after cidr constructor has been invoked
            db_api.subnet_update(self.context,
                                 sub_mod,
                                 next_auto_assign_ip=next_ip)
        yield net_mod

    def test_allocate_finds_ip_reallocates(self):
        network = dict(name="public", tenant_id="fake")
        ipnet = netaddr.IPNetwork("0.0.0.0/24")
        next_ip = ipnet.ipv6().first + 10
        subnet = dict(cidr="0.0.0.0/24", next_auto_assign_ip=next_ip,
                      ip_policy=None, tenant_id="fake", do_not_use=False)

        addr = netaddr.IPAddress("0.0.0.2")

        after_reuse_after = cfg.CONF.QUARK.ipam_reuse_after + 1
        reusable_after = datetime.timedelta(seconds=after_reuse_after)
        deallocated_at = timeutils.utcnow() - reusable_after
        ip_address = dict(address=addr, version=4, _deallocated=True,
                          deallocated_at=deallocated_at)

        with self._stubs(network, subnet, ip_address) as net:
            ipaddress = []
            self.ipam.allocate_ip_address(self.context, ipaddress,
                                          net["id"], 0, 0)
            self.assertIsNotNone(ipaddress[0]['id'])
            expected = netaddr.IPAddress("0.0.0.2").ipv6().value
            self.assertEqual(ipaddress[0]['address'], expected)
            self.assertEqual(ipaddress[0]['version'], 4)
            self.assertEqual(ipaddress[0]['used_by_tenant_id'], "fake")

    def test_allocate_finds_ip_in_do_not_use_subnet_raises(self):
        network = dict(name="public", tenant_id="fake")
        ipnet = netaddr.IPNetwork("0.0.0.0/24")
        next_ip = ipnet.ipv6().first + 3
        subnet = dict(cidr="0.0.0.0/24", next_auto_assign_ip=next_ip,
                      ip_policy=None, tenant_id="fake", do_not_use=True)

        addr = netaddr.IPAddress("0.0.0.2")
        after_reuse_after = cfg.CONF.QUARK.ipam_reuse_after + 1
        reusable_after = datetime.timedelta(seconds=after_reuse_after)
        deallocated_at = timeutils.utcnow() - reusable_after
        ip_address = dict(address=addr, version=4, _deallocated=True,
                          deallocated_at=deallocated_at)

        with self._stubs(network, subnet, ip_address) as net:
            with self.assertRaises(exceptions.IpAddressGenerationFailure):
                self.ipam.allocate_ip_address(self.context, [], net["id"],
                                              0, 0)


class QuarkIPAddressFindReallocatable(QuarkIpamBaseFunctionalTest):
    @contextlib.contextmanager
    def _stubs(self, network, subnet):
        self.ipam = quark.ipam.QuarkIpamANY()
        with self.context.session.begin():
            next_ip = subnet.pop("next_auto_assign_ip", 0)
            net_mod = db_api.network_create(self.context, **network)
            subnet["network"] = net_mod
            sub_mod = db_api.subnet_create(self.context, **subnet)
            # NOTE(asadoughi): update after cidr constructor has been invoked
            db_api.subnet_update(self.context,
                                 sub_mod,
                                 next_auto_assign_ip=next_ip)
        yield net_mod

    def test_find_reallocatable_ips_does_not_raise(self):
        """Regression testing

        A patch recently introduced a bug wherein addressses
        could not be returned to the ip_address_find call in
        attempt_to_reallocate_ip. Adding this test to prevent
        a future regression.
        """

        network = dict(name="public", tenant_id="fake")
        ipnet = netaddr.IPNetwork("0.0.0.0/24")
        next_ip = ipnet.ipv6().first + 2
        subnet = dict(id=1, cidr="0.0.0.0/24", next_auto_assign_ip=next_ip,
                      ip_policy=None, tenant_id="fake")

        with self._stubs(network, subnet) as net:
            ip_kwargs = {
                "network_id": net["id"], "reuse_after": 14400,
                "deallocated": True, "scope": db_api.ONE,
                "lock_mode": True, "version": 4,
                "order_by": "address"}

            try:
                db_api.ip_address_find(self.context, **ip_kwargs)
            except Exception:
                self.fail("This should not have raised")
