import netaddr

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


class QuarkIPPoliciesFirstLastIPTest(BaseFunctionalTest):
    def test_ip_policies_create(self):
        exclude_first_last = dict()
        for cidr in ("192.168.10.0/32", "192.168.10.255/32"):
            exclude_first_last[cidr] = netaddr.IPNetwork(cidr).ipv6().first
        ip_policy = db_api.ip_policy_create(
            self.context, exclude=exclude_first_last)
        self.assertEqual(len(ip_policy["exclude"]), 2)
        for ippc in ip_policy["exclude"]:
            self.assertEqual(exclude_first_last[ippc["cidr"]],
                             ippc["first_ip"])
            self.assertEqual(exclude_first_last[ippc["cidr"]],
                             ippc["last_ip"])

    def test_ip_policies_update(self):
        ip_policy_dict = dict(
            exclude=["192.168.10.0/32", "192.168.10.255/32"])
        ip_policy = db_api.ip_policy_create(self.context, **ip_policy_dict)
        new_exclude_first_last = dict()
        for cidr in ("192.168.10.0/32", "192.168.10.13/32",
                     "192.168.10.255/32"):
            new_exclude_first_last[cidr] = netaddr.IPNetwork(cidr).ipv6().first
        updated_ip_policy = db_api.ip_policy_update(
            self.context, ip_policy, exclude=new_exclude_first_last.keys())
        self.assertEqual(len(updated_ip_policy["exclude"]), 3)
        for ippc in updated_ip_policy["exclude"]:
            self.assertEqual(new_exclude_first_last[ippc["cidr"]],
                             ippc["first_ip"])
            self.assertEqual(new_exclude_first_last[ippc["cidr"]],
                             ippc["last_ip"])
