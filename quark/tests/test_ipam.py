from collections import namedtuple
from datetime import datetime
from sqlalchemy import create_engine
import mock

from oslo.config import cfg
from quantum import context
from quantum.common import exceptions
from quantum.db import api as db_api

from quark.db import models
import quark.ipam

import test_base


class TestQuarkIpamBase(test_base.TestBase):
    def setUp(self):
        cfg.CONF.set_override('sql_connection', 'sqlite://', 'DATABASE')
        db_api.configure_db()
        models.BASEV2.metadata.create_all(db_api._ENGINE)
        self.ipam = quark.ipam.QuarkIpam()
        self.context = context.get_admin_context()

    def tearDown(self):
        db_api.clear_db()

    def _create_and_insert_mar(self, base='01:02:03:00:00:00', mask=24):
        first_address = int(base.replace(':', ''), base=16)
        last_address = first_address + (1 << (48 - mask))
        mar = models.MacAddressRange(cidr=base + '/' + str(mask),
                                     first_address=first_address,
                                     last_address=last_address)
        self.context.session.add(mar)
        self.context.session.flush()

    def test_allocate_mac_address_no_ranges(self):
        net_id = None
        port_id = None
        tenant_id = None
        reuse_after = 0

        with self.assertRaises(exceptions.MacAddressGenerationFailure):
            self.ipam.allocate_mac_address(self.context.session,
                                           net_id,
                                           port_id,
                                           tenant_id,
                                           reuse_after)

    def test_allocate_mac_address_success(self):
        net_id = None
        port_id = None
        tenant_id = 'foobar'
        reuse_after = 0

        self._create_and_insert_mar()
        mar = self.context.session.query(models.MacAddressRange).first()

        mac = self.ipam.allocate_mac_address(self.context.session,
                                             net_id,
                                             port_id,
                                             tenant_id,
                                             reuse_after)

        self.assertEqual(mac['tenant_id'], tenant_id)
        self.assertIsNone(mac['created_at'])  # null pre-insert
        self.assertEqual(mac['address'], mar['first_address'])
        self.assertEqual(mac['mac_address_range_id'], mar['id'])
        self.assertFalse(mac['deallocated'])
        self.assertIsNone(mac['deallocated_at'])

    def test_allocate_mac_address_deallocated_success(self):
        net_id = None
        port_id = None
        tenant_id = 'foobar'
        reuse_after = 0

        self._create_and_insert_mar()
        mar = self.context.session.query(models.MacAddressRange).first()

        mac_deallocated = models.MacAddress(tenant_id=tenant_id,
                                            address=mar['first_address'],
                                            mac_address_range_id=mar['id'],
                                            deallocated=True,
                                            deallocated_at=datetime(1970,
                                                                    1,
                                                                    1))
        self.context.session.add(mac_deallocated)
        self.context.session.flush()

        mac = self.ipam.allocate_mac_address(self.context.session,
                                             net_id,
                                             port_id,
                                             tenant_id,
                                             reuse_after)

        self.assertEqual(mac['tenant_id'], tenant_id)
        self.assertIsNotNone(mac['created_at'])  # non-null post-insert
        self.assertEqual(mac['address'], mar['first_address'])
        self.assertEqual(mac['mac_address_range_id'], mar['id'])
        self.assertFalse(mac['deallocated'])
        self.assertIsNone(mac['deallocated_at'])

    def test_allocate_mac_address_deallocated_failure(self):
        '''Fails based on the choice of reuse_after argument. Allocates new mac
        address instead of previously deallocated mac address.'''
        net_id = None
        port_id = None
        tenant_id = 'foobar'
        reuse_after = 3600
        test_datetime = datetime(1970, 1, 1)
        deallocated_at = test_datetime

        self._create_and_insert_mar()
        mar = self.context.session.query(models.MacAddressRange).first()

        mac_deallocated = models.MacAddress(tenant_id=tenant_id,
                                            address=mar['first_address'],
                                            mac_address_range_id=mar['id'],
                                            deallocated=True,
                                            deallocated_at=deallocated_at)
        self.context.session.add(mac_deallocated)
        self.context.session.flush()

        with mock.patch('quark.ipam.timeutils') as timeutils:
            timeutils.utcnow.return_value = test_datetime
            mac = self.ipam.allocate_mac_address(self.context.session,
                                                 net_id,
                                                 port_id,
                                                 tenant_id,
                                                 reuse_after)

            self.assertEqual(mac['tenant_id'], tenant_id)
            self.assertIsNone(mac['created_at'])  # null pre-insert
            self.assertEqual(mac['address'], mar['first_address'] + 1)
            self.assertEqual(mac['mac_address_range_id'], mar['id'])
            self.assertFalse(mac['deallocated'])
            self.assertIsNone(mac['deallocated_at'])

    def test_allocate_mac_address_second_mac(self):
        net_id = None
        port_id = None
        tenant_id = 'foobar'
        reuse_after = 0

        self._create_and_insert_mar()
        mar = self.context.session.query(models.MacAddressRange).first()

        mac = models.MacAddress(tenant_id=tenant_id,
                                address=mar['first_address'],
                                mac_address_range_id=mar['id'],
                                deallocated=False,
                                deallocated_at=None)
        self.context.session.add(mac)
        self.context.session.flush()

        mac2 = self.ipam.allocate_mac_address(self.context.session,
                                              net_id,
                                              port_id,
                                              tenant_id,
                                              reuse_after)

        self.assertEqual(mac2['tenant_id'], tenant_id)
        self.assertIsNone(mac2['created_at'])  # null pre-insert
        self.assertEqual(mac2['address'], mar['first_address'] + 1)
        self.assertEqual(mac2['mac_address_range_id'], mar['id'])
        self.assertFalse(mac2['deallocated'])
        self.assertIsNone(mac2['deallocated_at'])

    def test_allocate_mac_address_fully_allocated_range(self):
        net_id = None
        port_id = None
        tenant_id = 'foobar'
        reuse_after = 0

        self._create_and_insert_mar(mask=48)
        mar = self.context.session.query(models.MacAddressRange).first()

        mac = models.MacAddress(tenant_id=tenant_id,
                                address=mar['first_address'],
                                mac_address_range_id=mar['id'],
                                deallocated=False,
                                deallocated_at=None)
        self.context.session.add(mac)
        self.context.session.flush()

        with self.assertRaises(exceptions.MacAddressGenerationFailure):
            self.ipam.allocate_mac_address(self.context.session,
                                           net_id,
                                           port_id,
                                           tenant_id,
                                           reuse_after)

    def test_allocate_mac_address_multiple_ranges(self):
        '''Tests that new address is allocated in m.a.r. that has the most macs
        allocated to it.'''
        net_id = None
        port_id = None
        tenant_id = 'foobar'
        reuse_after = 0

        self._create_and_insert_mar()
        mar = self.context.session.query(models.MacAddressRange).first()

        mac = models.MacAddress(tenant_id=tenant_id,
                                address=mar['first_address'],
                                mac_address_range_id=mar['id'],
                                deallocated=False,
                                deallocated_at=None)
        self.context.session.add(mac)
        self.context.session.flush()

        self._create_and_insert_mar(base='01:02:04:00:00:00')

        mac = self.ipam.allocate_mac_address(self.context.session,
                                             net_id,
                                             port_id,
                                             tenant_id,
                                             reuse_after)

        self.assertEqual(mac['tenant_id'], tenant_id)
        self.assertIsNone(mac['created_at'])  # null pre-insert
        self.assertEqual(mac['address'], mar['first_address'] + 1)
        self.assertEqual(mac['mac_address_range_id'], mar['id'])
        self.assertFalse(mac['deallocated'])
        self.assertIsNone(mac['deallocated_at'])

    def test_deallocate_mac_address_failure(self):
        with self.assertRaises(exceptions.NotFound):
            self.ipam.deallocate_mac_address(self.context.session,
                                             '01:02:04:00:00:00')

    def test_deallocate_mac_address_success(self):
        net_id = None
        port_id = None
        tenant_id = 'foobar'
        reuse_after = 0

        self._create_and_insert_mar()
        mar = self.context.session.query(models.MacAddressRange).first()

        mac = models.MacAddress(tenant_id=tenant_id,
                                address=mar['first_address'],
                                mac_address_range_id=mar['id'],
                                deallocated=False,
                                deallocated_at=None)
        self.context.session.add(mac)
        self.context.session.flush()

        test_datetime = datetime(1970, 1, 1)
        with mock.patch('quark.ipam.timeutils') as timeutils:
            timeutils.utcnow.return_value = test_datetime
            self.ipam.deallocate_mac_address(self.context.session,
                                             mar['first_address'])

        mac = self.context.session.query(models.MacAddress).first()
        self.assertTrue(mac['deallocated'])
        self.assertEqual(mac['deallocated_at'], test_datetime)

    def test_allocate_ip_address_deallocated_success(self):
        pass

    def test_allocate_ip_address_deallocated_failure(self):
        pass

    def test_allocate_ip_address_no_subnets_failure(self):
        net_id = None
        port_id = None
        reuse_after = 0
        with self.assertRaises(exceptions.IpAddressGenerationFailure):
            self.ipam.allocate_ip_address(self.context.session,
                                          net_id,
                                          port_id,
                                          reuse_after)

    def test_allocate_ip_address_fully_allocated_subnet(self):
        pass

    def test_allocate_ip_address_multiple_subnets(self):
        pass

    def test_allocate_ip_address_success(self):
        pass

    def test_allocate_ip_address_multiple_ips(self):
        pass

    def test_deallocate_ip_address_success(self):
        pass

    def test_deallocate_ip_address_failure(self):
        pass
