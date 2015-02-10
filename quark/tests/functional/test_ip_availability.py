import datetime

import mock
import netaddr
from neutron.db import api as neutron_db_api
from oslo.config import cfg

from quark.db import models
from quark import ip_availability as ip_avail
from quark.tests.functional.base import BaseFunctionalTest


class QuarkIpAvailBaseFunctionalTest(BaseFunctionalTest):
    def setUp(self):
        super(QuarkIpAvailBaseFunctionalTest, self).setUp()
        self.connection = neutron_db_api.get_engine().connect()
        self.networks = models.BASEV2.metadata.tables["quark_networks"]
        self.subnets = models.BASEV2.metadata.tables["quark_subnets"]
        self.ip_policy = models.BASEV2.metadata.tables[
            "quark_ip_policy"]
        self.ip_policy_cidr = models.BASEV2.metadata.tables[
            "quark_ip_policy_cidrs"]
        self.ip_addresses = models.BASEV2.metadata.tables[
            "quark_ip_addresses"]

    def _insert_ip_policy(self, id=0, excludes=None):
        if not excludes:
            excludes = (0, 255)
        self.connection.execute(
            self.ip_policy.insert(),
            dict(id=id, size=len(excludes)))
        self.connection.execute(
            self.ip_policy_cidr.insert(),
            [dict(ip_policy_id=id, first_ip=x, last_ip=x)
             for x in excludes])

    def _insert_network(self, id="00000000-0000-0000-0000-000000000000"):
        self.connection.execute(self.networks.insert(), dict(id=id))

    def _insert_subnet(self,
                       do_not_use=0,
                       id=0,
                       network_id="00000000-0000-0000-0000-000000000000",
                       cidr="0.0.0.0/24",
                       tenant_id="rackspace",
                       ip_policy_id=0,
                       ip_version=4):
        self.connection.execute(
            self.subnets.insert(),
            dict(do_not_use=do_not_use,
                 _cidr=cidr,
                 network_id=network_id,
                 ip_version=ip_version,
                 tenant_id=tenant_id,
                 id=id,
                 ip_policy_id=ip_policy_id))

    def _insert_ip_address(self,
                           address=1,
                           address_readable="0.0.0.1",
                           subnet_id=0,
                           deallocated=0,
                           deallocated_at=None):
        self.connection.execute(
            self.ip_addresses.insert(),
            dict(address=address,
                 address_readable=address_readable,
                 subnet_id=subnet_id,
                 _deallocated=deallocated,
                 deallocated_at=deallocated_at))

    def _default(self):
        self._insert_ip_policy()
        self._insert_network()
        self._insert_subnet()
        self._insert_ip_address()

    def _do_not_use_None(self):
        self._insert_ip_policy()
        self._insert_network()
        self._insert_subnet(do_not_use=None)
        self._insert_ip_address()

    def _do_not_use_1(self):
        self._insert_ip_policy()
        self._insert_network()
        self._insert_subnet(do_not_use=1)
        self._insert_ip_address()

    def _network_id_not_publicnet(self):
        self._insert_ip_policy()
        self._insert_network(id="foo")
        self._insert_subnet(network_id="foo")
        self._insert_ip_address()

    def _ip_version_None(self):
        self._insert_ip_policy()
        self._insert_network()
        self._insert_subnet(ip_version=None)
        self._insert_ip_address()

    def _ip_version_6(self):
        net6 = netaddr.IPNetwork('::ffff:0.0.0.0/120')
        self._insert_ip_policy(excludes=(net6.first, net6.last))
        self._insert_network()
        self._insert_subnet(cidr=str(net6.cidr), ip_version=6)
        address = net6.first + 1
        self._insert_ip_address(
            address=address,
            address_readable=str(netaddr.IPAddress(address)))

    def _tenant_id_like_percent_dash_percent(self):
        self._insert_ip_policy()
        self._insert_network()
        self._insert_subnet(tenant_id="foo-bar")
        self._insert_ip_address()

    def _tenant_id_None(self):
        self._insert_ip_policy()
        self._insert_network()
        self._insert_subnet(tenant_id=None)
        self._insert_ip_address()

    def _no_ip_addresses(self):
        self._insert_ip_policy()
        self._insert_network()
        self._insert_subnet()

    def _no_ip_addresses_no_ip_policy(self):
        self._insert_network()
        self._insert_subnet(ip_policy_id=None)

    def _no_ip_policy(self, utcnow_patch):
        self._insert_network()

        base = datetime.datetime(2015, 2, 13)
        utcnow_patch.return_value = base
        delta = datetime.timedelta(seconds=cfg.CONF.QUARK.ipam_reuse_after)
        reuse_window = base - delta
        epsilon = datetime.timedelta(seconds=1)

        address_readable = {0: "0.0.0.0",
                            1: "0.0.0.1",
                            255: "0.0.0.255"}
        subnet_id = 0
        for deallocated in (None, 0, 1):
            for deallocated_at in (None,
                                   reuse_window - epsilon,
                                   reuse_window,
                                   reuse_window + epsilon):
                for address in address_readable:
                    self._insert_subnet(id=subnet_id, ip_policy_id=None)
                    self._insert_ip_address(
                        subnet_id=subnet_id,
                        address=address,
                        deallocated=deallocated,
                        deallocated_at=deallocated_at,
                        address_readable=address_readable[address])
                    subnet_id += 1

    def _with_ip_policy(self, utcnow_patch):
        self._insert_network()
        self._insert_ip_policy()

        base = datetime.datetime(2015, 2, 13)
        utcnow_patch.return_value = base
        delta = datetime.timedelta(seconds=cfg.CONF.QUARK.ipam_reuse_after)
        reuse_window = base - delta
        epsilon = datetime.timedelta(seconds=1)

        address_readable = {0: "0.0.0.0",
                            1: "0.0.0.1",
                            255: "0.0.0.255"}
        subnet_id = 0
        for deallocated in (None, 0, 1):
            for deallocated_at in (None,
                                   reuse_window - epsilon,
                                   reuse_window,
                                   reuse_window + epsilon):
                for address in address_readable:
                    self._insert_subnet(id=subnet_id)
                    self._insert_ip_address(
                        subnet_id=subnet_id,
                        address=address,
                        deallocated=deallocated,
                        deallocated_at=deallocated_at,
                        address_readable=address_readable[address])
                    subnet_id += 1


class QuarkIpAvailGetUsedIpsTest(QuarkIpAvailBaseFunctionalTest):
    def test_get_used_ips_empty(self):
        used_ips = ip_avail.get_used_ips(neutron_db_api.get_session())
        self.assertEqual(used_ips, {})

    def test_default(self):
        self._default()
        used_ips = ip_avail.get_used_ips(neutron_db_api.get_session())
        self.assertEqual(used_ips, dict(rackspace=1))

    def test_do_not_use_None(self):
        self._do_not_use_None()
        used_ips = ip_avail.get_used_ips(neutron_db_api.get_session())
        self.assertEqual(used_ips, dict(rackspace=1))

    def test_do_not_use_1(self):
        self._do_not_use_1()
        used_ips = ip_avail.get_used_ips(neutron_db_api.get_session())
        self.assertEqual(used_ips, dict())

    def test_network_id_not_publicnet(self):
        self._network_id_not_publicnet()
        used_ips = ip_avail.get_used_ips(neutron_db_api.get_session())
        self.assertEqual(used_ips, dict())

    def test_ip_version_None(self):
        self._ip_version_None()
        used_ips = ip_avail.get_used_ips(neutron_db_api.get_session())
        self.assertEqual(used_ips, dict())

    def test_ip_version_6(self):
        self._ip_version_6()
        used_ips = ip_avail.get_used_ips(neutron_db_api.get_session())
        self.assertEqual(used_ips, dict())

    def test_tenant_id_like_percent_dash_percent(self):
        self._tenant_id_like_percent_dash_percent()
        used_ips = ip_avail.get_used_ips(neutron_db_api.get_session())
        self.assertEqual(used_ips, {"foo-bar": 1})

    def test_tenant_id_None(self):
        self._tenant_id_None()
        used_ips = ip_avail.get_used_ips(neutron_db_api.get_session())
        self.assertEqual(used_ips, dict())

    def test_no_ip_addresses(self):
        self._no_ip_addresses()
        used_ips = ip_avail.get_used_ips(neutron_db_api.get_session())
        self.assertEqual(used_ips, dict(rackspace=0))

    def test_no_ip_addresses_no_ip_policy(self):
        self._no_ip_addresses_no_ip_policy()
        used_ips = ip_avail.get_used_ips(neutron_db_api.get_session())
        self.assertEqual(used_ips, dict(rackspace=0))

    @mock.patch("quark.ip_availability.timeutils.utcnow")
    def test_no_ip_policy(self, utcnow_patch):
        self._no_ip_policy(utcnow_patch)
        used_ips = ip_avail.get_used_ips(neutron_db_api.get_session())
        self.assertEqual(used_ips, dict(rackspace=27))

    @mock.patch("quark.ip_availability.timeutils.utcnow")
    def test_with_ip_policy(self, utcnow_patch):
        self._with_ip_policy(utcnow_patch)
        used_ips = ip_avail.get_used_ips(neutron_db_api.get_session())
        self.assertEqual(used_ips, dict(rackspace=25))


class QuarkIpAvailGetUnusedIpsTest(QuarkIpAvailBaseFunctionalTest):
    def test_get_unused_ips_empty(self):
        used_ips = {}
        unused_ips = ip_avail.get_unused_ips(neutron_db_api.get_session(),
                                             used_ips)
        self.assertEqual(unused_ips, {})

    def test_default(self):
        self._default()
        used_ips = dict(rackspace=1)
        unused_ips = ip_avail.get_unused_ips(neutron_db_api.get_session(),
                                             used_ips)
        self.assertEqual(unused_ips, dict(rackspace=253))

    def test_do_not_use_None(self):
        self._do_not_use_None()
        used_ips = dict(rackspace=1)
        unused_ips = ip_avail.get_unused_ips(neutron_db_api.get_session(),
                                             used_ips)
        self.assertEqual(unused_ips, dict(rackspace=253))

    def test_do_not_use_1(self):
        self._do_not_use_1()
        used_ips = dict()
        unused_ips = ip_avail.get_unused_ips(neutron_db_api.get_session(),
                                             used_ips)
        self.assertEqual(unused_ips, dict())

    def test_network_id_not_publicnet(self):
        self._network_id_not_publicnet()
        used_ips = dict()
        unused_ips = ip_avail.get_unused_ips(neutron_db_api.get_session(),
                                             used_ips)
        self.assertEqual(unused_ips, dict())

    def test_ip_version_None(self):
        self._ip_version_None()
        used_ips = dict()
        unused_ips = ip_avail.get_unused_ips(neutron_db_api.get_session(),
                                             used_ips)
        self.assertEqual(unused_ips, dict())

    def test_ip_version_6(self):
        self._ip_version_6()
        used_ips = dict()
        unused_ips = ip_avail.get_unused_ips(neutron_db_api.get_session(),
                                             used_ips)
        self.assertEqual(unused_ips, dict())

    def test_tenant_id_like_percent_dash_percent(self):
        self._tenant_id_like_percent_dash_percent()
        used_ips = {"foo-bar": 1}
        unused_ips = ip_avail.get_unused_ips(neutron_db_api.get_session(),
                                             used_ips)
        self.assertEqual(unused_ips, {"foo-bar": 253})

    def test_tenant_id_None(self):
        self._tenant_id_None()
        used_ips = dict()
        unused_ips = ip_avail.get_unused_ips(neutron_db_api.get_session(),
                                             used_ips)
        self.assertEqual(unused_ips, dict())

    def test_no_ip_addresses(self):
        self._no_ip_addresses()
        used_ips = dict(rackspace=0)
        unused_ips = ip_avail.get_unused_ips(neutron_db_api.get_session(),
                                             used_ips)
        self.assertEqual(unused_ips, dict(rackspace=254))

    def test_no_ip_addresses_no_ip_policy(self):
        self._no_ip_addresses_no_ip_policy()
        used_ips = dict(rackspace=0)
        unused_ips = ip_avail.get_unused_ips(neutron_db_api.get_session(),
                                             used_ips)
        self.assertEqual(unused_ips, dict(rackspace=256))

    @mock.patch("quark.ip_availability.timeutils.utcnow")
    def test_no_ip_policy(self, utcnow_patch):
        self._no_ip_policy(utcnow_patch)
        used_ips = dict(rackspace=27)
        unused_ips = ip_avail.get_unused_ips(neutron_db_api.get_session(),
                                             used_ips)
        self.assertEqual(unused_ips, dict(rackspace=256 * 36 - 27))

    @mock.patch("quark.ip_availability.timeutils.utcnow")
    def test_with_ip_policy(self, utcnow_patch):
        self._with_ip_policy(utcnow_patch)
        used_ips = dict(rackspace=25)
        unused_ips = ip_avail.get_unused_ips(neutron_db_api.get_session(),
                                             used_ips)
        self.assertEqual(unused_ips, dict(rackspace=254 * 36 - 25))
