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

RESOURCE_NAME = 'ip_address'
RESOURCE_COLLECTION = RESOURCE_NAME + "es"
EXTENDED_ATTRIBUTES_2_0 = {
    RESOURCE_COLLECTION: {}
}

attr_dict = EXTENDED_ATTRIBUTES_2_0[RESOURCE_COLLECTION]
attr_dict[RESOURCE_NAME] = {'allow_post': True,
                            'allow_put': True,
                            'is_visible': True}

SUB_RESOURCE_ATTRIBUTE_MAP = {
    'ports': {
        'parent': {'collection_name': 'ip_addresses',
                   'member_name': 'ip_address'}
    }
}

LOG = logging.getLogger(__name__)


class IpAddressesController(wsgi.Controller):

    def __init__(self, plugin):
        self._resource_name = RESOURCE_NAME
        self._plugin = plugin

    def index(self, request):
        context = request.context
        return {"ip_addresses":
                self._plugin.get_ip_addresses(context, **request.GET)}

    def show(self, request, id):
        context = request.context
        try:
            return {"ip_address":
                    self._plugin.get_ip_address(context, id)}
        except n_exc.NotFound as e:
            raise webob.exc.HTTPNotFound(e)

    def create(self, request, body=None):
        body = self._deserialize(request.body, request.get_content_type())
        try:
            return {"ip_address": self._plugin.create_ip_address(
                    request.context, body)}
        except n_exc.NotFound as e:
            raise webob.exc.HTTPNotFound(e)
        except n_exc.Conflict as e:
            raise webob.exc.HTTPConflict(e)
        except n_exc.BadRequest as e:
            raise webob.exc.HTTPBadRequest(e)

    def update(self, request, id, body=None):
        body = self._deserialize(request.body, request.get_content_type())
        try:
            return {"ip_address": self._plugin.update_ip_address(
                    request.context, id, body)}
        except n_exc.NotFound as e:
            raise webob.exc.HTTPNotFound(e)
        except n_exc.BadRequest as e:
            raise webob.exc.HTTPBadRequest(e)

    def delete(self, request, id):
        context = request.context
        try:
            return self._plugin.delete_ip_address(context, id)
        except n_exc.NotFound as e:
            raise webob.exc.HTTPNotFound(e)
        except n_exc.BadRequest as e:
            raise webob.exc.HTTPBadRequest(e)


class IpAddressPortController(wsgi.Controller):

    def __init__(self, plugin):
        self._resource_name = RESOURCE_NAME
        self._plugin = plugin

    def _clean_query_string(self, request, filters):
        clean_list = ['id', 'device_id', 'service']
        for clean in clean_list:
            if clean in request.GET:
                filters[clean] = request.GET[clean]
                del request.GET[clean]

    def index(self, ip_address_id, request):
        context = request.context
        filters = {}
        self._clean_query_string(request, filters)
        fx = self._plugin.get_ports_for_ip_address
        try:
            ports = fx(context, ip_address_id, filters=filters, **request.GET)
            return {"ip_addresses_ports": ports}
        except n_exc.NotFound as e:
            raise webob.exc.HTTPNotFound(e)

    def create(self, request, **kwargs):
        raise webob.exc.HTTPNotImplemented()

    def show(self, ip_address_id, request, id):
        context = request.context
        # TODO(jlh): need to ensure ip_address_id is used to filter port
        try:
            return {"ip_addresses_port":
                    self._plugin.get_port_for_ip_address(context,
                                                         ip_address_id, id)}
        except n_exc.NotFound as e:
            raise webob.exc.HTTPNotFound(e)

    def update(self, ip_address_id, request, id, body=None):
        body = self._deserialize(request.body, request.get_content_type())
        try:
            return {"ip_addresses_port": self._plugin.update_port_for_ip(
                request.context, ip_address_id, id, body)}
        except n_exc.NotFound as e:
            raise webob.exc.HTTPNotFound(e)
        except n_exc.BadRequest as e:
            raise webob.exc.HTTPBadRequest(e)

    def delete(self, request, id, **kwargs):
        raise webob.exc.HTTPNotImplemented()


class Ip_addresses(extensions.ExtensionDescriptor):
    """IP Addresses support."""
    @classmethod
    def get_name(cls):
        return "IP Addresses for a tenant"

    @classmethod
    def get_alias(cls):
        return RESOURCE_COLLECTION

    @classmethod
    def get_description(cls):
        return "Expose functions for tenant IP Address management"

    @classmethod
    def get_namespace(cls):
        return ("http://docs.openstack.org/network/ext/"
                "ip_addresses/api/v2.0")

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
        ip_controller = IpAddressesController(
            manager.NeutronManager.get_plugin())
        ip_port_controller = IpAddressPortController(
            manager.NeutronManager.get_plugin())
        resources = []
        resources.append(extensions.ResourceExtension(
                         Ip_addresses.get_alias(),
                         ip_controller))
        parent = {'collection_name': 'ip_addresses',
                  'member_name': 'ip_address'}
        resources.append(extensions.ResourceExtension(
                         'ports', ip_port_controller, parent=parent))
        return resources
