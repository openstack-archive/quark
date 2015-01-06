from neutron.db import api as neutron_db_api

from quark import ip_availability as ip_avail
from quark.tests.functional.base import BaseFunctionalTest


class QuarkIpAvailBaseFunctionalTest(BaseFunctionalTest):
    pass


class QuarkIpAvailGetUsedIpsTest(QuarkIpAvailBaseFunctionalTest):
    def test_get_used_ips_empty(self):
        used_ips = ip_avail.get_used_ips(neutron_db_api.get_session())
        self.assertEqual(used_ips, {})


class QuarkIpAvailGetUnusedIpsTest(QuarkIpAvailBaseFunctionalTest):
    def test_get_unused_ips_empty(self):
        used_ips = {}
        unused_ips = ip_avail.get_unused_ips(neutron_db_api.get_session(),
                                             used_ips)
        self.assertEqual(unused_ips, {})
