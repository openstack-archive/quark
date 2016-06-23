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

from neutron.api import extensions
from neutron import manager
from neutron import wsgi
from neutron_lib import exceptions as n_exc
from oslo_log import log as logging
import webob

RESOURCE_NAME = 'job'
RESOURCE_COLLECTION = RESOURCE_NAME + "s"
EXTENDED_ATTRIBUTES_2_0 = {
    RESOURCE_COLLECTION: {
        "completed": {"allow_post": False, "is_visible": True,
                      "default": False}}
}

attr_dict = EXTENDED_ATTRIBUTES_2_0[RESOURCE_COLLECTION]
attr_dict[RESOURCE_NAME] = {'allow_post': True,
                            'allow_put': True,
                            'is_visible': True}

LOG = logging.getLogger(__name__)


class JobsController(wsgi.Controller):

    def __init__(self, plugin):
        self._resource_name = RESOURCE_NAME
        self._plugin = plugin

    def index(self, request):
        context = request.context
        return {"jobs": self._plugin.get_jobs(context, **request.GET)}

    def show(self, request, id):
        context = request.context
        try:
            return {"job": self._plugin.get_job(context, id)}
        except n_exc.NotFound as e:
            raise webob.exc.HTTPNotFound(e)

    def create(self, request, body=None):
        context = request.context
        body = self._deserialize(request.body, request.get_content_type())
        try:
            return {"job": self._plugin.create_job(context, body)}
        except n_exc.NotFound as e:
            raise webob.exc.HTTPNotFound(e)
        except n_exc.Conflict as e:
            raise webob.exc.HTTPConflict(e)
        except n_exc.BadRequest as e:
            raise webob.exc.HTTPBadRequest(e)

    def update(self, request, id, body=None):
        context = request.context
        body = self._deserialize(request.body, request.get_content_type())
        try:
            return {"job": self._plugin.update_job(context, id, body)}
        except n_exc.NotFound as e:
            raise webob.exc.HTTPNotFound(e)
        except n_exc.BadRequest as e:
            raise webob.exc.HTTPBadRequest(e)

    def delete(self, request, id):
        context = request.context
        try:
            return self._plugin.delete_job(context, id)
        except n_exc.NotFound as e:
            raise webob.exc.HTTPNotFound(e)
        except n_exc.BadRequest as e:
            raise webob.exc.HTTPBadRequest(e)


class Jobs(extensions.ExtensionDescriptor):
    """Jobs support."""
    @classmethod
    def get_name(cls):
        return "Asyncronous jobs for a tenant"

    @classmethod
    def get_alias(cls):
        return RESOURCE_COLLECTION

    @classmethod
    def get_description(cls):
        return "Provide a way to track asyncronous jobs"

    @classmethod
    def get_namespace(cls):
        return ("http://docs.openstack.org/network/ext/"
                "ip_addresses/api/v2.0")

    @classmethod
    def get_updated(cls):
        return "2016-05-15T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        job_controller = JobsController(
            manager.NeutronManager.get_plugin())
        resources = []
        resources.append(extensions.ResourceExtension(
                         Jobs.get_alias(),
                         job_controller))
        return resources
