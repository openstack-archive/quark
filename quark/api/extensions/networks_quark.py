# Copyright (c) 2013 Rackspace Hosting Inc.
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


from neutron.api import extensions

RESOURCE_NAME = "network"
RESOURCE_COLLECTION = RESOURCE_NAME + "s"
EXTENDED_ATTRIBUTES_2_0 = {
    RESOURCE_COLLECTION: {
        "ipam_strategy": {"allow_post": True, "is_visible": True,
                          "default": False},
        "network_plugin": {"allow_post": True, "is_visible": False,
                           "default": False},
        "id": {"allow_post": True, "is_visible": True, "default": False}}}


class Networks_quark(extensions.ExtensionDescriptor):
    """Extends Networks for quark API purposes."""

    @classmethod
    def get_name(cls):
        return "Quark Networks API Extension"

    @classmethod
    def get_alias(cls):
        return "networks_quark"

    @classmethod
    def get_description(cls):
        return "Quark Networks API Extension"

    @classmethod
    def get_namespace(cls):
        return ("http://docs.openstack.org/network/ext/"
                "networks_quark/api/v2.0")

    @classmethod
    def get_updated(cls):
        return "2013-03-25T19:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
