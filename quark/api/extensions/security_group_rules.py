# Copyright (c) 2016 Rackspace Hosting Inc.
# All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from neutron.api import extensions

EXTENDED_ATTRIBUTES_2_0 = {
    "security_group_rules": {
        "external_service": {"allow_post": True,
                             "allow_put": True,
                             "default": None,
                             "is_visible": True},
        "external_service_id": {"allow_post": True,
                                "allow_put": True,
                                "default": None,
                                "is_visible": True}
    }
}


class Security_group_rules(extensions.ExtensionDescriptor):
    """Extends Security Group Rules for FAWS purposes."""

    @classmethod
    def get_name(cls):
        return 'Quark security-group-rules extension'

    @classmethod
    def get_alias(cls):
        # NOTE(alexm): This string must be listed in
        # supported_extension_aliases in quark/plugin.py
        return 'faws-security-group-rule-ext'

    @classmethod
    def get_description(cls):
        return 'Quark Security Group Rules API Extension'

    @classmethod
    def get_namespace(cls):
        return ("http://docs.openstack.org/api/openstack-network/2.0/content/"
                "SecurityGroupRules.html")

    @classmethod
    def get_updated(cls):
        return "2016-09-15T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
