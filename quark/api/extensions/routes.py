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
from neutron_lib import exceptions as n_exc
from oslo_log import log as logging
import webob

RESOURCE_NAME = 'route'
RESOURCE_COLLECTION = RESOURCE_NAME + "s"
EXTENDED_ATTRIBUTES_2_0 = {
    RESOURCE_COLLECTION: {}
}

attr_dict = EXTENDED_ATTRIBUTES_2_0[RESOURCE_COLLECTION]
attr_dict[RESOURCE_NAME] = {'allow_post': True,
                            'allow_put': True,
                            'is_visible': True}

LOG = logging.getLogger(__name__)


def route_dict(route):
    return dict(cidr=route["cidr"],
                gateway=route["gateway"],
                id=route["id"],
                subnet_id=route["subnet_id"])


class RoutesController(wsgi.Controller):

    def __init__(self, plugin):
        self._resource_name = RESOURCE_NAME
        self._plugin = plugin

    def create(self, request, body=None):
        body = self._deserialize(request.body, request.get_content_type())
        keys = ["subnet_id", "gateway", "cidr"]
        for k in keys:
            if k not in body[RESOURCE_NAME]:
                raise webob.exc.HTTPUnprocessableEntity()

        return {"route":
                self._plugin.create_route(request.context, body)}

    def index(self, request):
        context = request.context
        return {"routes":
                self._plugin.get_routes(context)}

    def show(self, request, id):
        context = request.context
        try:
            return {"route": self._plugin.get_route(context, id)}
        except n_exc.NotFound:
            raise webob.exc.HTTPNotFound()

    def delete(self, request, id):
        context = request.context
        try:
            self._plugin.delete_route(context, id)
        except n_exc.NotFound:
            raise webob.exc.HTTPNotFound()


class Routes(extensions.ExtensionDescriptor):
    """Routes support."""
    @classmethod
    def get_name(cls):
        return "Routes for a tenant"

    @classmethod
    def get_alias(cls):
        return RESOURCE_COLLECTION

    @classmethod
    def get_description(cls):
        return "Expose functions for tenant route management"

    @classmethod
    def get_namespace(cls):
        return "http://docs.openstack.org/network/ext/routes/api/v2.0"

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
        """Returns Ext Resources."""
        controller = RoutesController(manager.NeutronManager.get_plugin())
        return [extensions.ResourceExtension(
            Routes.get_alias(),
            controller)]
