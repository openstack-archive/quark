import os

from neutron import context
from neutron.db import api as neutron_db_api
from oslo_config import cfg
from sqlalchemy.orm import configure_mappers

from quark.db import models
from quark import quota_driver
from quark.tests import test_base


class MySqlBaseFunctionalTest(test_base.TestBase):
    @classmethod
    def setUpClass(cls):
        default = 'mysql://root@localhost/quark_functional_tests'
        sql_string = os.getenv('QUARK_MYSQL_TESTS_URL', default)
        cfg.CONF.set_override(
            'connection',
            sql_string,
            'database')
        cfg.CONF.set_override(
            'max_retries',
            1,
            'database')
        cfg.CONF.set_override(
            'retry_interval',
            0,
            'database')
        cfg.CONF.set_override(
            'connection_debug',
            '0',
            'database')

    def setUp(self):
        super(MySqlBaseFunctionalTest, self).setUp()
        self.context = context.Context('fake', 'fake', is_admin=False)
        configure_mappers()
        engine = neutron_db_api.get_engine()
        models.BASEV2.metadata.create_all(engine)
        quota_driver.Quota.metadata.create_all(engine)

    def tearDown(self):
        engine = neutron_db_api.get_engine()
        models.BASEV2.metadata.drop_all(engine)
        quota_driver.Quota.metadata.drop_all(engine)
