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
from neutron.api.v2 import attributes as attr
from neutron.api.v2 import resource_helper
from oslo_log import log as logging


LOG = logging.getLogger(__name__)


def _validate_list_of_port_dicts(values, data):
    if not isinstance(values, list):
        msg = _("'%s' is not a list") % data
        return msg

    for item in values:
        msg = _validate_port_dict(item)
        if msg:
            return msg

    items = [tuple(entry.items()) for entry in values]
    if len(items) != len(set(items)):
        msg = _("Duplicate items in the list: '%s'") % values
        return msg


def _validate_port_dict(values):
    if not isinstance(values, dict):
        msg = _("%s is not a valid dictionary") % values
        LOG.debug(msg)
        return msg
    port_id = values.get('port_id')
    fixed_ip = values.get('fixed_ip_address')
    msg = attr._validate_uuid(port_id)
    if msg:
        return msg
    if fixed_ip is None:
        return
    msg = attr._validate_ip_address(fixed_ip)
    if msg:
        return msg

attr.validators['type:validate_list_of_port_dicts'] = (
    _validate_list_of_port_dicts
)

RESOURCE_NAME = "scalingip"
RESOURCE_COLLECTION = RESOURCE_NAME + "s"

RESOURCE_ATTRIBUTE_MAP = {
    RESOURCE_COLLECTION: {
        'id': {
            'allow_post': False, 'allow_put': False,
            'validate': {'type:uuid': None},
            'is_visible': True,
            'primary_key': True
        },
        "scaling_ip_address": {
            'allow_post': True, 'allow_put': False,
            'validate': {'type:ip_address_or_none': None},
            'is_visible': True, 'default': None,
            'enforce_policy': True
        },
        "tenant_id": {
            'allow_post': True, 'allow_put': False,
            'required_by_policy': True,
            'validate': {'type:string': attr.TENANT_ID_MAX_LEN},
            'is_visible': True
        },
        "scaling_network_id": {
            'allow_post': True, 'allow_put': False,
            'validate': {'type:uuid': None},
            'is_visible': True
        },
        "ports": {
            'allow_post': True, 'allow_put': True,
            'validate': {
                'type:validate_list_of_port_dicts': None
            },
            'is_visible': True,
            'required_by_policy': True
        }
    }
}


class Scalingip(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return RESOURCE_NAME

    @classmethod
    def get_alias(cls):
        return RESOURCE_NAME

    @classmethod
    def get_description(cls):
        return "Scaling IPs"

    @classmethod
    def get_namespace(cls):
        return ("http://docs.openstack.org/network/ext/"
                "networks_quark/api/v2.0")

    @classmethod
    def get_updated(cls):
        return "2016-01-20T19:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        plural_mappings = resource_helper.build_plural_mappings(
            {}, RESOURCE_ATTRIBUTE_MAP)
        attr.PLURALS.update(plural_mappings)
        return resource_helper.build_resource_info(plural_mappings,
                                                   RESOURCE_ATTRIBUTE_MAP,
                                                   None,
                                                   register_quota=True)

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}
