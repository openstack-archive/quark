# Copyright 2013 Openstack Foundation
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
#  under the License.

from netaddr import IPSet
from quark.db import models
from quark.tests import test_base


class TestDBModels(test_base.TestBase):
    def setUp(self):
        super(TestDBModels, self).setUp()

    def test_get_ip_policy_rule_set(self):
        subnet = dict(id=1, ip_version=4, next_auto_assign_ip=0,
                      cidr="0.0.0.0/24", first_ip=0, last_ip=255,
                      network=dict(ip_policy=None), ip_policy=None)
        ip_policy_rules = models.IPPolicy.get_ip_policy_rule_set(subnet)
        self.assertEqual(ip_policy_rules,
                         IPSet(['0.0.0.0/31', '0.0.0.255/32']))
