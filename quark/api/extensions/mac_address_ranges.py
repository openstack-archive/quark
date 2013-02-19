# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 OpenStack LLC.
# All Rights Reserved.
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

import webob

from quantum.api import extensions
from quantum.api.v2 import base
from quantum.manager import QuantumManager
from quantum.openstack.common import log as logging
from quantum import wsgi

RESOURCE_NAME = 'mac_address_range'
RESOURCE_COLLECTION = RESOURCE_NAME + "s"
EXTENDED_ATTRIBUTES_2_0 = {
    RESOURCE_COLLECTION: {}
}

attr_dict = EXTENDED_ATTRIBUTES_2_0[RESOURCE_COLLECTION]
attr_dict[RESOURCE_NAME] = {'allow_post': True,
                            'allow_put': False,
                            'is_visible': True}

LOG = logging.getLogger("quantum")


def mac_range_dict(mac_range):
    return dict(address=mac_range["cidr"],
                id=mac_range["id"])


class MacAddressRangesController(wsgi.Controller):

    def __init__(self, plugin):
        self._resource_name = RESOURCE_NAME
        self._plugin = plugin

    def _get_body(self, request):
        body = self._deserialize(request.body, request.get_content_type())
        attr_info = EXTENDED_ATTRIBUTES_2_0[RESOURCE_COLLECTION]
        req_body = base.Controller.prepare_request_body(
            request.context, body, False, self._resource_name, attr_info)
        return req_body

    def create(self, request, body=None):
        body = self._get_body(request)
        return {"mac_address_range":
                 self._plugin.create_mac_address_range(request.context, body)}

    def index(self, request):
        context = request.context
        if not context.is_admin:
            raise webob.exc.HTTPForbidden()
        return {"mac_address_ranges":
                        self._plugin.get_mac_address_ranges(context)}

    def show(self, request, id):
        context = request.context
        tenant_id = id
        if not tenant_id:
            raise webob.exc.HTTPBadRequest('invalid tenant')
        return self._plugin.get_mac_address_range(context, id)


class Mac_address_ranges(object):
    """Quotas management support"""
    @classmethod
    def get_name(cls):
        return "MAC Address Ranges for a tenant"

    @classmethod
    def get_alias(cls):
        return RESOURCE_COLLECTION

    @classmethod
    def get_description(cls):
        return ("Expose functions for cloud admin to manage MAC ranges"
                "for each tenant")

    @classmethod
    def get_namespace(cls):
        return ("http://docs.openstack.org/network/ext/"
                "mac-address-ranges/api/v2.0")

    @classmethod
    def get_updated(cls):
        return "2013-02-19T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}

    @classmethod
    def get_resources(cls):
        """ Returns Ext Resources """
        controller = MacAddressRangesController(QuantumManager.get_plugin())
        return [extensions.ResourceExtension(
            Mac_address_ranges.get_alias(),
            controller)]
