# Copyright (c) 2013 OpenStack Foundation
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
from neutron import manager
from neutron import wsgi

RESOURCE_NAME = "port"
RESOURCE_COLLECTION = RESOURCE_NAME + "s"
EXTENDED_ATTRIBUTES_2_0 = {
    RESOURCE_COLLECTION: {
        "network_id": {"allow_post": True, "default": '',
                       "is_visible": True},
        "tenant_id": {"allow_post": True, "default": '',
                      "is_visible": True},
        "segment_id": {"allow_post": True, "default": False},
        "bridge": {'allow_post': False, 'allow_put': False,
                   'default': False, 'is_visible': True}}}


class QuarkPortsUpdateHandler(object):
    def __init__(self, plugin):
        self._plugin = plugin

    def handle(self, request, response):
        deserializer = wsgi.JSONDeserializer()
        serializer = wsgi.JSONDictSerializer()

        path = [part for part in request.path_url.split("/") if part]
        id = path[-1].split('.')[0]

        body = None
        if request.body:
            body = deserializer.deserialize(request.body)['body']

        api_response = self._plugin.post_update_port(request.context,
                                                     id,
                                                     body)
        return serializer.serialize({"port": api_response})


class Ports_quark(object):
    """Extends ports for quark API purposes.

    * Allows for DELETE (disassociation of port) with IP address
    * Allows for POST with fixed_ip in body to associate additional IPs
    """

    @classmethod
    def get_name(cls):
        return "Quark Ports API Extension"

    @classmethod
    def get_alias(cls):
        return "ports_quark"

    @classmethod
    def get_description(cls):
        return "Quark Ports API Extension"

    @classmethod
    def get_namespace(cls):
        return ("http://docs.openstack.org/network/ext/"
                "port_disassociate/api/v2.0")

    @classmethod
    def get_updated(cls):
        return "2013-03-25T19:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}

    @classmethod
    def get_request_extensions(cls):
        exts = []

        quark_ports_update_handler = QuarkPortsUpdateHandler(
            manager.NeutronManager.get_plugin())
        extension = extensions.RequestExtension(
            "POST", "/ports/:(id)",
            quark_ports_update_handler.handle)
        exts.append(extension)

        return exts
