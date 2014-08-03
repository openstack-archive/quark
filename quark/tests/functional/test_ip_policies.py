from neutron import context
from neutron.db import api as neutron_db_api
from oslo.config import cfg
import unittest2

from quark.db import api as db_api
from quark.db import models


class QuarkIPPoliciesFunctionalTest(unittest2.TestCase):
    def setUp(self):
        self.context = context.Context('fake', 'fake', is_admin=False)
        super(QuarkIPPoliciesFunctionalTest, self).setUp()

        cfg.CONF.set_override('connection', 'sqlite://', 'database')
        neutron_db_api.configure_db()
        neutron_db_api.register_models(models.BASEV2)

    def tearDown(self):
        neutron_db_api.unregister_models(models.BASEV2)
        neutron_db_api.clear_db()


class QuarkIPPoliciesSizeTest(QuarkIPPoliciesFunctionalTest):
    def test_ip_policies_create(self):
        ip_policy_dict = dict(
            exclude=["192.168.10.0/32", "192.168.10.255/32"])
        ip_policy = db_api.ip_policy_create(self.context, **ip_policy_dict)
        self.assertEqual(ip_policy["size"], 2)

    def test_ip_policies_update(self):
        ip_policy_dict = dict(
            exclude=["192.168.10.0/32", "192.168.10.255/32"])
        ip_policy = db_api.ip_policy_create(self.context, **ip_policy_dict)
        ip_policy_update_dict = dict(
            exclude=["192.168.10.0/32", "192.168.10.13/32",
                     "192.168.10.255/32"])
        updated_ip_policy = db_api.ip_policy_update(
            self.context, ip_policy, **ip_policy_update_dict)
        self.assertEqual(updated_ip_policy["size"], 3)
