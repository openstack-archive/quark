import netaddr

from quark.db import api as db_api
from quark.tests.functional.mysql.base import MySqlBaseFunctionalTest

from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class QuarkLocks(MySqlBaseFunctionalTest):
    def test_create_lock_holder(self):
        kwargs = {"address": netaddr.IPAddress("192.168.2.1")}
        ip_address = db_api.ip_address_create(self.context, **kwargs)
        kwargs = {"type": "ip_address", "name": "because i said so"}
        lock_holder = db_api.lock_holder_create(
            self.context, ip_address, **kwargs)

        self.context.session.refresh(ip_address)
        self.assertEqual(ip_address.lock_id, lock_holder.lock_id)

    def test_create_lock_holder_already_locked(self):
        kwargs = {"address": netaddr.IPAddress("192.168.2.1")}
        ip_address = db_api.ip_address_create(self.context, **kwargs)
        name = "because i said so"
        kwargs_1 = {"type": "ip_address", "name": name + "1"}
        lock_holder_1 = db_api.lock_holder_create(
            self.context, ip_address, **kwargs_1)
        self.context.session.flush()

        kwargs_2 = {"type": "ip_address", "name": name + "2"}
        self.context.session.refresh(ip_address)
        lock_holder_2 = db_api.lock_holder_create(
            self.context, ip_address, **kwargs_2)
        self.context.session.flush()

        self.context.session.refresh(ip_address)
        self.assertNotEqual(lock_holder_1.id, lock_holder_2.id)
        self.assertEqual(lock_holder_1.name, name + "1")
        self.assertEqual(lock_holder_2.name, name + "2")
        self.assertEqual(lock_holder_1.lock_id, lock_holder_2.lock_id)
        self.assertEqual(ip_address.lock_id, lock_holder_1.lock_id)

    def test_find_lock_holder(self):
        kwargs = {"address": netaddr.IPAddress("192.168.2.1")}
        ip_address = db_api.ip_address_create(self.context, **kwargs)
        kwargs = {"type": "ip_address", "name": "because i said so"}
        lock_holder = db_api.lock_holder_create(
            self.context, ip_address, **kwargs)

        self.context.session.refresh(ip_address)
        self.assertEqual(ip_address.lock_id, lock_holder.lock_id)

        lock_holders = db_api.lock_holder_find(
            self.context,
            lock_id=ip_address.lock_id, name=kwargs["name"],
            scope=db_api.ALL)
        self.assertEqual(len(lock_holders), 1)
        self.assertEqual(lock_holders[0]["lock_id"], ip_address.lock_id)
        self.assertEqual(lock_holders[0]["name"], kwargs["name"])

    def test_delete_lock_holder(self):
        kwargs = {"address": netaddr.IPAddress("192.168.2.1")}
        ip_address = db_api.ip_address_create(self.context, **kwargs)
        kwargs = {"type": "ip_address", "name": "because i said so"}
        lock_holder = db_api.lock_holder_create(
            self.context, ip_address, **kwargs)
        self.context.session.flush()
        self.context.session.refresh(ip_address)
        self.assertEqual(ip_address.lock_id, lock_holder.lock_id)

        db_api.lock_holder_delete(self.context, ip_address, lock_holder)
        self.context.session.refresh(ip_address)
        self.assertIsNone(ip_address.lock_id)
