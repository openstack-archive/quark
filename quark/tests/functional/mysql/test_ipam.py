import contextlib
import datetime

import mock
import netaddr
from neutron.common import exceptions as n_exc_ext
from neutron.common import rpc
from neutron_lib import exceptions as n_exc
from oslo_config import cfg
from oslo_utils import timeutils

from quark.db import api as db_api
import quark.ipam
from quark.tests.functional.mysql.base import MySqlBaseFunctionalTest


class QuarkIpamBaseFunctionalTest(MySqlBaseFunctionalTest):
    def setUp(self):
        super(QuarkIpamBaseFunctionalTest, self).setUp()

        patcher = mock.patch("neutron.common.rpc.oslo_messaging")
        patcher.start()
        self.addCleanup(patcher.stop)
        rpc.init(mock.MagicMock())


class QuarkIPAddressReallocate(QuarkIpamBaseFunctionalTest):
    @contextlib.contextmanager
    def _stubs(self, network, subnet, address, lock=False):
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
            ip = db_api.ip_address_update(self.context, ip, **address)

            # NOTE(asadoughi): update after cidr constructor has been invoked
            db_api.subnet_update(self.context,
                                 sub_mod,
                                 next_auto_assign_ip=next_ip)

        if lock:
            db_api.lock_holder_create(self.context, ip,
                                      name="testlock", type="ip_address")
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
            with self.assertRaises(n_exc.IpAddressGenerationFailure):
                self.ipam.allocate_ip_address(self.context, [], net["id"],
                                              0, 0)

    def test_allocate_finds_ip_locked_allocates_next_ip(self):
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

        with self._stubs(network, subnet, ip_address, lock=True) as net:
            ipaddress = []
            self.ipam.allocate_ip_address(self.context, ipaddress,
                                          net["id"], 0, 0)
            self.assertIsNotNone(ipaddress[0]['id'])
            self.assertEqual(ipaddress[0]['address'], next_ip)
            self.assertEqual(ipaddress[0]['version'], 4)
            self.assertEqual(ipaddress[0]['used_by_tenant_id'], "fake")


class MacAddressReallocate(QuarkIpamBaseFunctionalTest):
    @contextlib.contextmanager
    def _stubs(self, do_not_use):
        self.ipam = quark.ipam.QuarkIpamANY()
        mar = db_api.mac_address_range_create(
            self.context,
            cidr="00:00:00:00:00:00/40",
            first_address=0, last_address=255,
            next_auto_assign_mac=6,
            do_not_use=do_not_use)
        mac = db_api.mac_address_create(
            self.context,
            address=1,
            mac_address_range=mar)
        db_api.mac_address_update(
            self.context, mac,
            deallocated=True,
            deallocated_at=datetime.datetime(1970, 1, 1))
        self.context.session.flush()
        yield mar

    def test_reallocate_mac(self):
        with self._stubs(do_not_use=False):
            realloc_mac = self.ipam.allocate_mac_address(self.context, 0, 0, 0)
            self.assertEqual(realloc_mac["address"], 1)

    def test_delete_mac_with_mac_range_do_not_use(self):
        macs = lambda mar: db_api.mac_address_find(
            self.context,
            mac_address_range_id=mar["id"],
            scope=db_api.ALL)
        with self._stubs(do_not_use=True) as mar:
            self.assertEqual(len(macs(mar)), 1)
            with self.assertRaises(n_exc_ext.MacAddressGenerationFailure):
                self.ipam.allocate_mac_address(self.context, 0, 0, 0)
            self.assertEqual(len(macs(mar)), 0)
