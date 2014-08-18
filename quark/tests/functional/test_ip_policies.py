from quark.db import api as db_api
from quark.tests.functional.base import BaseFunctionalTest


class QuarkIPPoliciesSizeTest(BaseFunctionalTest):
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
