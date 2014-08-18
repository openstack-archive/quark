from neutron import context
from neutron.db import api as neutron_db_api
from oslo.config import cfg
from sqlalchemy.orm import configure_mappers

from quark.db import models
from quark.tests import test_base


class BaseFunctionalTest(test_base.TestBase):
    def setUp(self):
        super(BaseFunctionalTest, self).setUp()
        self.context = context.Context('fake', 'fake', is_admin=False)
        cfg.CONF.set_override('connection', 'sqlite://', 'database')
        configure_mappers()
        models.BASEV2.metadata.create_all(neutron_db_api.get_engine())

    def tearDown(self):
        models.BASEV2.metadata.drop_all(neutron_db_api.get_engine())
