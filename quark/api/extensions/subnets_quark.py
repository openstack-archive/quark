# Copyright (c) 2013 Rackspace Hosting Inc.
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
    "subnets": {
        "segment_id": {"allow_post": True, "default": None},
        "ip_policy_id": {"allow_post": False, "allow_put": False,
                         "default": None, "is_visible": True}
    }
}


class Subnets_quark(extensions.ExtensionDescriptor):
    """Extends subnets for quark API purposes.

    * Shunts enable_dhcp to false
    """

    @classmethod
    def get_name(cls):
        return "Quark Subnets API Extension"

    @classmethod
    def get_alias(cls):
        return "subnets_quark"

    @classmethod
    def get_description(cls):
        return "Quark Subnets API Extension"

    @classmethod
    def get_namespace(cls):
        return ("http://docs.openstack.org/api/openstack-network/2.0/content/"
                "Subnets.html")

    @classmethod
    def get_updated(cls):
        return "2013-04-22T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
