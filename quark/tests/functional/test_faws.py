# Copyright (c) 2016 Rackspace Hosting Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from neutron import context
from neutron_lib import exceptions as n_exc

from quark import plugin
from quark.api.extensions import security_groups
from quark.api.extensions import security_group_rules
from quark.tests.functional.base import BaseFunctionalTest


class QuarkFAWSTest(BaseFunctionalTest):
    def setUp(self):
        super(QuarkFAWSTest, self).setUp()
        self.plugin = plugin.Plugin()
        self.version = '2.0'

class QuarkPluginSecurityGroupsTest(QuarkFAWSTest):

    def test_supported_extension_aliases(self):
        self.assertTrue('faws-security-group-ext' in
                        self.plugin.supported_extension_aliases)
        self.assertTrue('faws-security-group-rule-ext' in
                        self.plugin.supported_extension_aliases)

    def test_security_group_extension(self):
        self.assertTrue('faws-security-group-ext' == \
                        security_groups.Security_groups.get_alias())
        sg = security_groups.Security_groups()
        self.assertTrue('security_groups' in
                        sg.get_extended_resources(self.version))
        attrs = sg.get_extended_resources(self.version)['security_groups']
        self.assertTrue('external_service' in attrs)
        self.assertTrue('external_service_id' in attrs)

    def test_security_group_rule_extension(self):
        self.assertTrue('faws-security-group-rule-ext' == \
                        security_group_rules.Security_group_rules.get_alias())
        sgr = security_group_rules.Security_group_rules()
        self.assertTrue('security_group_rules' in
                        sgr.get_extended_resources(self.version))
        attrs = sgr.get_extended_resources(self.version)\
                ['security_group_rules']
        self.assertTrue('external_service' in attrs)
        self.assertTrue('external_service_id' in attrs)
