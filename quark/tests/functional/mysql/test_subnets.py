from sqlalchemy.orm import exc

from quark.db import api as db_api
from quark.tests.functional.mysql.base import MySqlBaseFunctionalTest


class TestSubnetsAllocationPoolCache(MySqlBaseFunctionalTest):
    def setUp(self):
        super(TestSubnetsAllocationPoolCache, self).setUp()

    def test_subnet_update_set_alloc_pool_cache_concurrency(self):
        subnet = {"cidr": "192.168.10.0/24"}
        subnet_db = db_api.subnet_create(self.context, **subnet)
        self.context.session.flush()

        # establish second session
        old_session = self.context.session
        self.context._session = None

        subnet_to_delete = db_api.subnet_find(
            self.context, id=subnet_db.id, scope=db_api.ONE)
        db_api.subnet_delete(self.context, subnet_to_delete)
        self.context.session.flush()

        # restore first session
        self.context._session = old_session

        try:
            db_api.subnet_update_set_alloc_pool_cache(
                self.context, subnet_db, {"foo": "bar"})
            self.context.session.flush()
        except exc.StaleDataError as e:
            self.fail("Did not expect StaleDataError exception: {0}".format(e))
        self.assertEqual(subnet_db["_allocation_pool_cache"],
                         "{\"foo\": \"bar\"}")
