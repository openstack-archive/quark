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
from neutron import manager
from neutron import wsgi
from oslo_log import log as logging
import quark.utils as utils

RESOURCE_NAME = "ip_policy"
RESOURCE_COLLECTION = "ip_policies"
EXTENDED_ATTRIBUTES_2_0 = {
    RESOURCE_COLLECTION: {}
}

attr_dict = EXTENDED_ATTRIBUTES_2_0[RESOURCE_COLLECTION]
attr_dict[RESOURCE_NAME] = {'allow_post': True,
                            'allow_put': False,
                            'is_visible': True}

LOG = logging.getLogger(__name__)


class IPPoliciesController(wsgi.Controller):
    def __init__(self, plugin):
        self._resource_name = RESOURCE_NAME
        self._plugin = plugin

    @utils.exc_wrapper
    def create(self, request, body=None):
        body = self._deserialize(request.body, request.get_content_type())
        return {RESOURCE_NAME:
                self._plugin.create_ip_policy(request.context, body)}

    @utils.exc_wrapper
    def update(self, request, id, body=None):
        body = self._deserialize(request.body, request.get_content_type())
        return {RESOURCE_NAME:
                self._plugin.update_ip_policy(request.context, id, body)}

    @utils.exc_wrapper
    def index(self, request):
        context = request.context
        return {RESOURCE_COLLECTION:
                self._plugin.get_ip_policies(context)}

    @utils.exc_wrapper
    def show(self, request, id):
        context = request.context
        return {RESOURCE_NAME: self._plugin.get_ip_policy(context, id)}

    @utils.exc_wrapper
    def delete(self, request, id, **kwargs):
        context = request.context
        return self._plugin.delete_ip_policy(context, id)


class Ip_policies(extensions.ExtensionDescriptor):
    """IP Policies support."""
    @classmethod
    def get_name(cls):
        return "IP Policies for a Neutron deployment"

    @classmethod
    def get_alias(cls):
        return RESOURCE_COLLECTION

    @classmethod
    def get_description(cls):
        return ("Expose functions for cloud admin to manage IP Policies"
                "for each tenant")

    @classmethod
    def get_namespace(cls):
        return ("http://docs.openstack.org/network/ext/"
                "ip-policies/api/v2.0")

    @classmethod
    def get_updated(cls):
        return "2013-06-19T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        plugin = manager.NeutronManager.get_plugin()
        controller = IPPoliciesController(plugin)
        return [extensions.ResourceExtension(Ip_policies.get_alias(),
                                             controller)]
