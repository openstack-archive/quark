from neutron import context
from neutron.db import api as neutron_db_api
from oslo.config import cfg
from sqlalchemy.orm import configure_mappers

from quark.db import models
from quark import quota_driver
from quark.tests import test_base


class BaseFunctionalTest(test_base.TestBase):
    def setUp(self):
        super(BaseFunctionalTest, self).setUp()
        self.context = context.Context('fake', 'fake', is_admin=False)
        cfg.CONF.set_override('connection', 'sqlite://', 'database')
        configure_mappers()
        engine = neutron_db_api.get_engine()
        models.BASEV2.metadata.create_all(engine)
        quota_driver.quota_db.Quota.metadata.create_all(engine)

    def tearDown(self):
        engine = neutron_db_api.get_engine()
        models.BASEV2.metadata.drop_all(engine)
        quota_driver.quota_db.Quota.metadata.drop_all(engine)
