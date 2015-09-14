import datetime

import mock
import netaddr
from neutron.db import api as neutron_db_api
from oslo_config import cfg

from quark.db import models
from quark import ip_availability as ip_avail
from quark.tests.functional.base import BaseFunctionalTest


EPOCH = datetime.date(1970, 1, 1)


class QuarkIpAvailabilityBaseFunctionalTest(BaseFunctionalTest):
    def setUp(self):
        super(QuarkIpAvailabilityBaseFunctionalTest, self).setUp()
        self.connection = neutron_db_api.get_engine().connect()
        self.networks = models.BASEV2.metadata.tables["quark_networks"]
        self.subnets = models.BASEV2.metadata.tables["quark_subnets"]
        self.ip_policy = models.BASEV2.metadata.tables[
            "quark_ip_policy"]
        self.ip_policy_cidr = models.BASEV2.metadata.tables[
            "quark_ip_policy_cidrs"]
        self.ip_addresses = models.BASEV2.metadata.tables[
            "quark_ip_addresses"]
        self.locks = models.BASEV2.metadata.tables[
            "quark_locks"]
        self.default_kwargs = {
            "network_id": "00000000-0000-0000-0000-000000000000",
            "ip_version": 4}

    def _insert_ip_policy(self, id=0, excludes=None):
        if not excludes:
            excludes = (0, 255)
        self.connection.execute(
            self.ip_policy.insert(),
            id=id, size=len(excludes), created_at=EPOCH)
        self.connection.execute(
            self.ip_policy_cidr.insert(),
            [dict(ip_policy_id=id, first_ip=x, last_ip=x, created_at=EPOCH)
             for x in excludes])

    def _insert_network(self, id="00000000-0000-0000-0000-000000000000"):
        self.connection.execute(self.networks.insert(),
                                id=id, created_at=EPOCH)

    def _insert_subnet(self,
                       do_not_use=0,
                       id=0,
                       network_id="00000000-0000-0000-0000-000000000000",
                       cidr="0.0.0.0/24",
                       segment_id="region-cell",
                       ip_policy_id=0,
                       ip_version=4):
        self.connection.execute(
            self.subnets.insert(),
            do_not_use=do_not_use,
            _cidr=cidr,
            network_id=network_id,
            ip_version=ip_version,
            segment_id=segment_id,
            id=id,
            ip_policy_id=ip_policy_id,
            created_at=EPOCH)

    def _insert_ip_address(self,
                           address=1,
                           address_readable="0.0.0.1",
                           subnet_id=0,
                           deallocated=0,
                           deallocated_at=None,
                           lock_id=None):
        self.connection.execute(
            self.ip_addresses.insert(),
            address=address,
            address_readable=address_readable,
            subnet_id=subnet_id,
            _deallocated=deallocated,
            deallocated_at=deallocated_at,
            lock_id=lock_id,
            created_at=EPOCH)

    def _insert_lock(self, id=0, type="ip_address"):
        self.connection.execute(
            self.locks.insert(),
            created_at=EPOCH,
            id=id,
            type=type)

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
        for lock in (None, 1):
            for deallocated in (None, 0, 1):
                for deallocated_at in (None,
                                       reuse_window - epsilon,
                                       reuse_window,
                                       reuse_window + epsilon):
                    for address in address_readable:
                        self._insert_subnet(id=subnet_id, ip_policy_id=None)
                        lock_id = None
                        if lock:
                            lock_id = subnet_id
                            self._insert_lock(id=lock_id)
                        self._insert_ip_address(
                            subnet_id=subnet_id,
                            address=address,
                            deallocated=deallocated,
                            deallocated_at=deallocated_at,
                            address_readable=address_readable[address],
                            lock_id=lock_id)
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
        for lock in (None, 1):
            for deallocated in (None, 0, 1):
                for deallocated_at in (None,
                                       reuse_window - epsilon,
                                       reuse_window,
                                       reuse_window + epsilon):
                    for address in address_readable:
                        self._insert_subnet(id=subnet_id)
                        lock_id = None
                        if lock:
                            lock_id = subnet_id
                            self._insert_lock(id=lock_id)
                        self._insert_ip_address(
                            subnet_id=subnet_id,
                            address=address,
                            deallocated=deallocated,
                            deallocated_at=deallocated_at,
                            address_readable=address_readable[address])
                        subnet_id += 1


class QuarkIpAvailabilityFunctionalTest(QuarkIpAvailabilityBaseFunctionalTest):
    def test_empty(self):
        output = ip_avail.get_ip_availability(**self.default_kwargs)
        self.assertEqual(output["used"], {})
        self.assertEqual(output["unused"], {})

    def test_default(self):
        self._default()
        output = ip_avail.get_ip_availability(**self.default_kwargs)
        self.assertEqual(output["used"], {"region-cell": 1})
        self.assertEqual(output["unused"], {"region-cell": 253})

    def test_do_not_use_None(self):
        self._do_not_use_None()
        output = ip_avail.get_ip_availability(**self.default_kwargs)
        self.assertEqual(output["used"], {"region-cell": 1})
        self.assertEqual(output["unused"], {"region-cell": 253})

    def test_do_not_use_1(self):
        self._do_not_use_1()
        output = ip_avail.get_ip_availability(**self.default_kwargs)
        self.assertEqual(output["used"], dict())
        self.assertEqual(output["unused"], dict())

    def test_no_ip_addresses(self):
        self._no_ip_addresses()
        output = ip_avail.get_ip_availability(**self.default_kwargs)
        self.assertEqual(output["used"], {"region-cell": 0})
        self.assertEqual(output["unused"], {"region-cell": 254})

    def test_no_ip_addresses_no_ip_policy(self):
        self._no_ip_addresses_no_ip_policy()
        output = ip_avail.get_ip_availability(**self.default_kwargs)
        self.assertEqual(output["used"], {"region-cell": 0})
        self.assertEqual(output["unused"], {"region-cell": 256})

    @mock.patch("quark.ip_availability.timeutils.utcnow")
    def test_no_ip_policy(self, utcnow_patch):
        self._no_ip_policy(utcnow_patch)
        output = ip_avail.get_ip_availability(**self.default_kwargs)
        self.assertEqual(output["used"], {"region-cell": 63})
        self.assertEqual(output["unused"], {"region-cell": 256 * 72 - 63})

    @mock.patch("quark.ip_availability.timeutils.utcnow")
    def test_with_ip_policy(self, utcnow_patch):
        self._with_ip_policy(utcnow_patch)
        output = ip_avail.get_ip_availability(**self.default_kwargs)
        self.assertEqual(output["used"], {"region-cell": 50})
        self.assertEqual(output["unused"], {"region-cell": 254 * 72 - 50})


class QuarkIpAvailabilityFilterTest(QuarkIpAvailabilityBaseFunctionalTest):
    def setUp(self):
        super(QuarkIpAvailabilityFilterTest, self).setUp()

        subnet_id = 0
        for network_id in (0, 1):
            self._insert_network(id=network_id)
            for segment_id in (0, 1):
                for ip_version in (4, 6):
                    ip_policy_id = subnet_id
                    if ip_version == 6:
                        net6 = netaddr.IPNetwork('::ffff:0.0.0.0/120')
                        excludes = (net6.first, net6.last)
                        cidr = str(net6.cidr)
                        address = net6.first + 1
                    else:
                        cidr = "0.0.0.0/24"
                        address = 1
                        excludes = (0, 255)

                    self._insert_ip_policy(
                        id=ip_policy_id,
                        excludes=excludes)
                    self._insert_subnet(
                        id=subnet_id,
                        network_id=network_id,
                        segment_id=segment_id,
                        ip_policy_id=ip_policy_id,
                        cidr=cidr,
                        ip_version=ip_version)
                    self._insert_ip_address(
                        subnet_id=subnet_id,
                        address=address,
                        address_readable=str(netaddr.IPAddress(address)))
                    subnet_id += 1

    def test_all_None(self):
        kwargs = {}
        output = ip_avail.get_ip_availability(**kwargs)
        self.assertEqual(output["used"], {"0": 4, "1": 4})
        self.assertEqual(output["unused"], {"0": 253 * 4, "1": 253 * 4})

    def test_network_id_specific(self):
        kwargs = {"network_id": 0}
        output = ip_avail.get_ip_availability(**kwargs)
        self.assertEqual(output["used"], {"0": 2, "1": 2})
        self.assertEqual(output["unused"], {"0": 253 * 2, "1": 253 * 2})

    def test_network_id_many(self):
        kwargs = {"network_id": [0, 1]}
        output = ip_avail.get_ip_availability(**kwargs)
        self.assertEqual(output["used"], {"0": 4, "1": 4})
        self.assertEqual(output["unused"], {"0": 253 * 4, "1": 253 * 4})

    def test_segment_id_specific(self):
        kwargs = {"segment_id": 0}
        output = ip_avail.get_ip_availability(**kwargs)
        self.assertEqual(output["used"], {"0": 4})
        self.assertEqual(output["unused"], {"0": 253 * 4})

    def test_segment_id_many(self):
        kwargs = {"segment_id": [0, 1]}
        output = ip_avail.get_ip_availability(**kwargs)
        self.assertEqual(output["used"], {"0": 4, "1": 4})
        self.assertEqual(output["unused"], {"0": 253 * 4, "1": 253 * 4})

    def test_ip_version_4(self):
        kwargs = {"ip_version": 4}
        output = ip_avail.get_ip_availability(**kwargs)
        self.assertEqual(output["used"], {"0": 2, "1": 2})
        self.assertEqual(output["unused"], {"0": 253 * 2, "1": 253 * 2})

    def test_ip_version_6(self):
        kwargs = {"ip_version": 6}
        output = ip_avail.get_ip_availability(**kwargs)
        self.assertEqual(output["used"], {"0": 2, "1": 2})
        self.assertEqual(output["unused"], {"0": 253 * 2, "1": 253 * 2})

    def test_ip_version_many(self):
        kwargs = {"ip_version": [4, 6]}
        output = ip_avail.get_ip_availability(**kwargs)
        self.assertEqual(output["used"], {"0": 4, "1": 4})
        self.assertEqual(output["unused"], {"0": 253 * 4, "1": 253 * 4})

    def test_subnet_id_specific(self):
        kwargs = {"subnet_id": 3}
        output = ip_avail.get_ip_availability(**kwargs)
        self.assertEqual(output["used"], {"1": 1})
        self.assertEqual(output["unused"], {"1": 253})

    def test_subnet_id_many(self):
        kwargs = {"subnet_id": [3, 4, 5]}
        output = ip_avail.get_ip_availability(**kwargs)
        self.assertEqual(output["used"], {"0": 2, "1": 1})
        self.assertEqual(output["unused"], {"0": 253 * 2, "1": 253})
