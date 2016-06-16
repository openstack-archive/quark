# Copyright (c) 2015 Rackspace Hosting Inc.
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
from neutron_lib import exceptions as n_exc
from oslo_log import log as logging

RESOURCE_NAME = "ip_availability"
RESOURCE_COLLECTION = "ip_availabilities"
EXTENDED_ATTRIBUTES_2_0 = {
    RESOURCE_COLLECTION: {}
}

attr_dict = EXTENDED_ATTRIBUTES_2_0[RESOURCE_COLLECTION]
attr_dict[RESOURCE_NAME] = {'allow_post': False,
                            'allow_put': False,
                            'is_visible': True}

LOG = logging.getLogger(__name__)


class IPAvailabilityController(wsgi.Controller):
    def __init__(self, plugin):
        self._resource_name = RESOURCE_NAME
        self._plugin = plugin

    def index(self, request):
        context = request.context
        if not context.is_admin:
            raise n_exc.NotAuthorized()
        return self._plugin.get_ip_availability(**request.GET)


class Ip_availability(extensions.ExtensionDescriptor):
    """IP Availability support."""
    @classmethod
    def get_name(cls):
        return "IP Availability for a Neutron deployment"

    @classmethod
    def get_alias(cls):
        return RESOURCE_COLLECTION

    @classmethod
    def get_description(cls):
        return ("Expose functions for cloud admin to get IP availability")

    @classmethod
    def get_namespace(cls):
        return ("http://docs.openstack.org/network/ext/"
                "ip-availability/api/v2.0")

    @classmethod
    def get_updated(cls):
        return "2015-02-18T00:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        plugin = manager.NeutronManager.get_plugin()
        controller = IPAvailabilityController(plugin)
        return [extensions.ResourceExtension(Ip_availability.get_alias(),
                                             controller)]
