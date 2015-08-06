import datetime

import netaddr
from oslo_utils import timeutils

from quark.db import api as db_api
from quark.plugin_modules import ip_policies
from quark.tests.functional.mysql.base import MySqlBaseFunctionalTest


class IPReallocateMixin(object):
    REUSE_AFTER = 300

    def insert_network(self):
        tenant_id = "foobar"
        network = {"tenant_id": tenant_id}
        network_db = db_api.network_create(self.context, **network)
        self.context.session.flush()
        return network_db

    def insert_subnet(self, network_db, cidr, do_not_use=False):
        subnet = {"network": network_db,
                  "cidr": cidr,
                  "ip_version": netaddr.IPNetwork(cidr).version,
                  "do_not_use": do_not_use}
        subnet_db = db_api.subnet_create(self.context, **subnet)
        self.context.session.flush()
        return subnet_db

    def insert_ip_address(self, ip_address, network_db, subnet_db):
        ip_address_db = db_api.ip_address_create(
            self.context,
            address=ip_address,
            version=ip_address.version,
            subnet_id=subnet_db["id"] if subnet_db else None,
            network_id=network_db["id"])

        ip_address_db["_deallocated"] = True
        ip_address_db["deallocated_at"] = (
            timeutils.utcnow() - datetime.timedelta(seconds=self.REUSE_AFTER))
        self.context.session.add(ip_address_db)
        self.context.session.flush()

        return ip_address_db

    def insert_transaction(self):
        with self.context.session.begin():
            transaction = db_api.transaction_create(self.context)
        return transaction

    def default_case(self):
        self.network_db = self.insert_network()
        self.subnet_v4_db = self.insert_subnet(
            self.network_db, "192.168.0.0/24")
        self.subnet_v6_db = self.insert_subnet(
            self.network_db, "ffcc::/7")
        self.ip_address_v4 = netaddr.IPAddress("192.168.0.1")
        self.insert_ip_address(self.ip_address_v4, self.network_db,
                               self.subnet_v4_db)
        self.ip_address_v6 = netaddr.IPAddress("ffcc::1")
        self.insert_ip_address(self.ip_address_v6, self.network_db,
                               self.subnet_v6_db)
        self.transaction = self.insert_transaction()

    def insert_default_ip_policy(self, subnet_db):
        cidrs = []
        ip_policies.ensure_default_policy(cidrs, [subnet_db])
        subnet_db["ip_policy"] = db_api.ip_policy_create(
            self.context, exclude=cidrs)
        self.context.session.add(subnet_db)
        self.context.session.flush()


class QuarkIPReallocateFunctionalTest(MySqlBaseFunctionalTest,
                                      IPReallocateMixin):
    def setUp(self):
        super(QuarkIPReallocateFunctionalTest, self).setUp()
        self.default_case()

    def test_normal_v4(self):
        ip_kwargs = {
            "network_id": self.network_db["id"],
            "reuse_after": self.REUSE_AFTER,
            "deallocated": True,
            "version": 4,
        }
        reallocated = db_api.ip_address_reallocate(
            self.context,
            {"transaction_id": self.transaction.id},
            **ip_kwargs)
        self.assertTrue(reallocated)

    def test_normal_v6(self):
        ip_kwargs = {
            "network_id": self.network_db["id"],
            "reuse_after": self.REUSE_AFTER,
            "deallocated": True,
            "version": 6,
        }
        reallocated = db_api.ip_address_reallocate(
            self.context,
            {"transaction_id": self.transaction.id},
            **ip_kwargs)
        self.assertTrue(reallocated)

    def test_ip_address_specified_deallocated_None(self):
        ip_kwargs = {
            "network_id": self.network_db["id"],
            "reuse_after": self.REUSE_AFTER,
            "ip_address": self.ip_address_v4,
            "version": 4,
        }
        reallocated = db_api.ip_address_reallocate(
            self.context,
            {"transaction_id": self.transaction.id},
            **ip_kwargs)
        self.assertTrue(reallocated)

    def test_subnet_ids_specified(self):
        ip_kwargs = {
            "network_id": self.network_db["id"],
            "reuse_after": self.REUSE_AFTER,
            "deallocated": True,
            "version": 4,
            "subnet_id": [self.subnet_v4_db["id"]]
        }
        reallocated = db_api.ip_address_reallocate(
            self.context,
            {"transaction_id": self.transaction.id},
            **ip_kwargs)
        self.assertTrue(reallocated)

    def test_reuse_after_not_time_yet(self):
        ip_kwargs = {
            "network_id": self.network_db["id"],
            "reuse_after": self.REUSE_AFTER * 2,
            "deallocated": True,
            "version": 4,
        }
        reallocated = db_api.ip_address_reallocate(
            self.context,
            {"transaction_id": self.transaction.id},
            **ip_kwargs)
        self.assertFalse(reallocated)

    def test_normal_one_of_multiple_potential_ip_addresses(self):
        ip_kwargs = {
            "network_id": self.network_db["id"],
            "reuse_after": self.REUSE_AFTER,
            "deallocated": True,
        }
        reallocated = db_api.ip_address_reallocate(
            self.context,
            {"transaction_id": self.transaction.id},
            **ip_kwargs)
        self.assertTrue(reallocated)


class QuarkIPReallocateFindTest(MySqlBaseFunctionalTest, IPReallocateMixin):
    def test_normal_v4(self):
        self.default_case()
        ip_kwargs = {
            "network_id": self.network_db["id"],
            "reuse_after": self.REUSE_AFTER,
            "deallocated": True,
            "version": 4,
        }
        reallocated = db_api.ip_address_reallocate(
            self.context,
            {"transaction_id": self.transaction.id},
            **ip_kwargs)
        self.assertTrue(reallocated)

        updated_address = db_api.ip_address_reallocate_find(
            self.context, self.transaction.id)
        self.assertEqual(updated_address["address"],
                         int(self.ip_address_v4.ipv6()))

    def test_normal_v6(self):
        self.default_case()
        ip_kwargs = {
            "network_id": self.network_db["id"],
            "reuse_after": self.REUSE_AFTER,
            "deallocated": True,
            "version": 6,
        }
        reallocated = db_api.ip_address_reallocate(
            self.context,
            {"transaction_id": self.transaction.id},
            **ip_kwargs)
        self.assertTrue(reallocated)

        updated_address = db_api.ip_address_reallocate_find(
            self.context, self.transaction.id)
        self.assertEqual(updated_address["address"],
                         int(self.ip_address_v6.ipv6()))

    def test_address_not_found(self):
        self.transaction = self.insert_transaction()

        updated_address = db_api.ip_address_reallocate_find(
            self.context, self.transaction.id)
        self.assertIsNone(updated_address)

    def test_subnet_null(self):
        self.network_db = self.insert_network()
        self.subnet_v4_db = self.insert_subnet(
            self.network_db, "192.168.0.0/24")
        self.ip_address_v4 = netaddr.IPAddress("192.168.0.1")
        self.insert_ip_address(self.ip_address_v4, self.network_db, None)
        self.transaction = self.insert_transaction()
        ip_kwargs = {
            "network_id": self.network_db["id"],
            "reuse_after": self.REUSE_AFTER,
            "deallocated": True,
            "version": 4,
        }
        reallocated = db_api.ip_address_reallocate(
            self.context,
            {"transaction_id": self.transaction.id},
            **ip_kwargs)
        self.assertTrue(reallocated)

        updated_address = db_api.ip_address_reallocate_find(
            self.context, self.transaction.id)
        self.assertIsNone(updated_address)

    def test_subnet_do_not_use(self):
        self.network_db = self.insert_network()
        self.subnet_v4_db = self.insert_subnet(
            self.network_db, "192.168.0.0/24", do_not_use=True)
        self.ip_address_v4 = netaddr.IPAddress("192.168.0.1")
        self.insert_ip_address(self.ip_address_v4, self.network_db,
                               self.subnet_v4_db)
        self.transaction = self.insert_transaction()
        ip_kwargs = {
            "network_id": self.network_db["id"],
            "reuse_after": self.REUSE_AFTER,
            "deallocated": True,
            "version": 4,
        }
        reallocated = db_api.ip_address_reallocate(
            self.context,
            {"transaction_id": self.transaction.id},
            **ip_kwargs)
        self.assertTrue(reallocated)

        updated_address = db_api.ip_address_reallocate_find(
            self.context, self.transaction.id)
        self.assertIsNone(updated_address)

    def test_policy_violation(self):
        self.network_db = self.insert_network()
        self.subnet_v4_db = self.insert_subnet(
            self.network_db, "192.168.0.0/24")
        self.ip_address_v4 = netaddr.IPAddress("192.168.0.0")
        ip_address_db = self.insert_ip_address(self.ip_address_v4,
                                               self.network_db,
                                               self.subnet_v4_db)
        self.transaction = self.insert_transaction()
        ip_kwargs = {
            "network_id": self.network_db["id"],
            "reuse_after": self.REUSE_AFTER,
            "deallocated": True,
            "version": 4,
        }
        reallocated = db_api.ip_address_reallocate(
            self.context,
            {"transaction_id": self.transaction.id},
            **ip_kwargs)
        self.assertTrue(reallocated)

        self.insert_default_ip_policy(self.subnet_v4_db)
        updated_address = db_api.ip_address_reallocate_find(
            self.context, self.transaction.id)
        self.assertIsNone(updated_address)

        self.context.session.flush()
        self.assertIsNone(db_api.ip_address_find(self.context,
                                                 id=ip_address_db.id,
                                                 scope=db_api.ONE))

    def test_address_not_in_cidr(self):
        self.network_db = self.insert_network()
        self.subnet_v4_db = self.insert_subnet(
            self.network_db, "192.168.0.0/24")
        self.ip_address_v4 = netaddr.IPAddress("192.168.1.1")
        ip_address_db = self.insert_ip_address(self.ip_address_v4,
                                               self.network_db,
                                               self.subnet_v4_db)
        self.transaction = self.insert_transaction()
        ip_kwargs = {
            "network_id": self.network_db["id"],
            "reuse_after": self.REUSE_AFTER,
            "deallocated": True,
            "version": 4,
        }
        reallocated = db_api.ip_address_reallocate(
            self.context,
            {"transaction_id": self.transaction.id},
            **ip_kwargs)
        self.assertTrue(reallocated)

        updated_address = db_api.ip_address_reallocate_find(
            self.context, self.transaction.id)
        self.assertIsNone(updated_address)

        self.context.session.flush()
        self.assertIsNone(db_api.ip_address_find(self.context,
                                                 id=ip_address_db.id,
                                                 scope=db_api.ONE))
