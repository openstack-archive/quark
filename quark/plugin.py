# Copyright 2013 Openstack Foundation
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

"""
v2 Neutron Plug-in API Quark Implementation
"""
from neutron.extensions import securitygroup as sg_ext
from neutron import neutron_plugin_base_v2
from neutron.openstack.common import log as logging
from neutron import quota
from oslo.config import cfg

from quark.api import extensions
from quark.plugin_modules import ip_addresses
from quark.plugin_modules import ip_policies
from quark.plugin_modules import mac_address_ranges
from quark.plugin_modules import networks
from quark.plugin_modules import ports
from quark.plugin_modules import routes
from quark.plugin_modules import security_groups
from quark.plugin_modules import subnets

LOG = logging.getLogger(__name__)

CONF = cfg.CONF

quark_resources = [
    quota.BaseResource('alloc_pools_per_subnet',
                       'quota_alloc_pools_per_subnet'),
    quota.BaseResource('dns_nameservers_per_subnet',
                       'quota_dns_nameservers_per_subnet'),
    quota.BaseResource('ports_per_network',
                       'quota_ports_per_network'),
    quota.BaseResource('routes_per_subnet',
                       'quota_routes_per_subnet'),
    quota.BaseResource('security_rules_per_group',
                       'quota_security_rules_per_group'),
    quota.BaseResource('security_groups_per_port',
                       'quota_security_groups_per_port'),
    quota.BaseResource('v4_subnets_per_network',
                       'quota_v4_subnets_per_network'),
    quota.BaseResource('v6_subnets_per_network',
                       'quota_v6_subnets_per_network')
]

quark_quota_opts = [
    cfg.IntOpt("quota_alloc_pools_per_subnet",
               default=5,
               help=_("Maximum number of allocation pools per subnet")),
    cfg.IntOpt('quota_dns_nameservers_per_subnet',
               default=2,
               help=_('Maximum number of dns nameservers per subnet')),
    cfg.IntOpt('quota_ports_per_network',
               default=250,
               help=_('Maximum ports per network')),
    cfg.IntOpt('quota_routes_per_subnet',
               default=3,
               help=_('Maximum routes per subnet')),
    cfg.IntOpt('quota_security_rules_per_group',
               default=20,
               help=_('Maximum security group rules in a group')),
    cfg.IntOpt("quota_security_groups_per_port",
               default=5,
               help=_("Maximum number of security groups per port")),
    cfg.IntOpt('quota_v4_subnets_per_network',
               default=1,
               help=_('Maximum v4 subnets per network')),
    cfg.IntOpt('quota_v6_subnets_per_network',
               default=1,
               help=_('Maximum v6 subnets per network'))
]


def append_quark_extensions(conf):
    """Adds the Quark API Extensions to the extension path.

    Pulled out for test coveage.
    """
    if 'api_extensions_path' in conf:
        conf.set_override('api_extensions_path', ":".join(extensions.__path__))

append_quark_extensions(CONF)


CONF.register_opts(quark_quota_opts, "QUOTAS")
quota.QUOTAS.register_resources(quark_resources)


def sessioned(func):
    def _wrapped(self, context, *args, **kwargs):
        res = func(self, context, *args, **kwargs)
        context.session.close()

        # NOTE(mdietz): Forces neutron to get a fresh session
        #              if it needs it after our call
        context._session = None
        return res
    return _wrapped


class Plugin(neutron_plugin_base_v2.NeutronPluginBaseV2,
             sg_ext.SecurityGroupPluginBase):
    supported_extension_aliases = ["mac_address_ranges", "routes",
                                   "ip_addresses", "ports_quark",
                                   "security-group", "diagnostics",
                                   "subnets_quark", "provider",
                                   "ip_policies", "quotas",
                                   "networks_quark", "router"]

    def __init__(self):
        LOG.info("Starting quark plugin")

    def _fix_missing_tenant_id(self, context, resource):
        """Will add the tenant_id to the context from body.

        It is assumed that the body must have a tenant_id because neutron
        core would have never got here in such a situation.
        """
        if context.tenant_id is None:
            context.tenant_id = resource["tenant_id"]

    @sessioned
    def get_mac_address_range(self, context, id, fields=None):
        return mac_address_ranges.get_mac_address_range(context, id, fields)

    @sessioned
    def get_mac_address_ranges(self, context):
        return mac_address_ranges.get_mac_address_ranges(context)

    @sessioned
    def create_mac_address_range(self, context, mac_range):
        self._fix_missing_tenant_id(context, mac_range["mac_address_range"])
        return mac_address_ranges.create_mac_address_range(context, mac_range)

    @sessioned
    def delete_mac_address_range(self, context, id):
        mac_address_ranges.delete_mac_address_range(context, id)

    @sessioned
    def create_security_group(self, context, security_group):
        self._fix_missing_tenant_id(context, security_group["security_group"])
        return security_groups.create_security_group(context, security_group)

    @sessioned
    def create_security_group_rule(self, context, security_group_rule):
        self._fix_missing_tenant_id(context,
                                    security_group_rule["security_group_rule"])
        return security_groups.create_security_group_rule(context,
                                                          security_group_rule)

    @sessioned
    def delete_security_group(self, context, id):
        security_groups.delete_security_group(context, id)

    @sessioned
    def delete_security_group_rule(self, context, id):
        security_groups.delete_security_group_rule(context, id)

    @sessioned
    def get_security_group(self, context, id, fields=None):
        return security_groups.get_security_group(context, id, fields)

    @sessioned
    def get_security_group_rule(self, context, id, fields=None):
        return security_groups.get_security_group_rule(context, id, fields)

    @sessioned
    def get_security_groups(self, context, filters=None, fields=None,
                            sorts=None, limit=None, marker=None,
                            page_reverse=False):
        return security_groups.get_security_groups(context, filters, fields,
                                                   sorts, limit, marker,
                                                   page_reverse)

    @sessioned
    def get_security_group_rules(self, context, filters=None, fields=None,
                                 sorts=None, limit=None, marker=None,
                                 page_reverse=False):
        return security_groups.get_security_group_rules(context, filters,
                                                        fields, sorts, limit,
                                                        marker, page_reverse)

    @sessioned
    def update_security_group(self, context, id, security_group):
        return security_groups.update_security_group(context, id,
                                                     security_group)

    @sessioned
    def create_ip_policy(self, context, ip_policy):
        self._fix_missing_tenant_id(context, ip_policy["ip_policy"])
        return ip_policies.create_ip_policy(context, ip_policy)

    @sessioned
    def get_ip_policy(self, context, id):
        return ip_policies.get_ip_policy(context, id)

    @sessioned
    def get_ip_policies(self, context, **filters):
        return ip_policies.get_ip_policies(context, **filters)

    @sessioned
    def update_ip_policy(self, context, id, ip_policy):
        return ip_policies.update_ip_policy(context, id, ip_policy)

    @sessioned
    def delete_ip_policy(self, context, id):
        return ip_policies.delete_ip_policy(context, id)

    @sessioned
    def get_ip_addresses(self, context, **filters):
        return ip_addresses.get_ip_addresses(context, **filters)

    @sessioned
    def get_ip_address(self, context, id):
        return ip_addresses.get_ip_address(context, id)

    @sessioned
    def create_ip_address(self, context, ip_address):
        self._fix_missing_tenant_id(context, ip_address["ip_address"])
        return ip_addresses.create_ip_address(context, ip_address)

    @sessioned
    def update_ip_address(self, context, id, ip_address):
        return ip_addresses.update_ip_address(context, id, ip_address)

    @sessioned
    def create_port(self, context, port):
        self._fix_missing_tenant_id(context, port["port"])
        return ports.create_port(context, port)

    @sessioned
    def post_update_port(self, context, id, port):
        return ports.post_update_port(context, id, port)

    @sessioned
    def get_port(self, context, id, fields=None):
        return ports.get_port(context, id, fields)

    @sessioned
    def update_port(self, context, id, port):
        return ports.update_port(context, id, port)

    @sessioned
    def get_ports(self, context, filters=None, fields=None):
        return ports.get_ports(context, filters, fields)

    @sessioned
    def get_ports_count(self, context, filters=None):
        return ports.get_ports_count(context, filters)

    @sessioned
    def delete_port(self, context, id):
        return ports.delete_port(context, id)

    @sessioned
    def disassociate_port(self, context, id, ip_address_id):
        return ports.disassociate_port(context, id, ip_address_id)

    @sessioned
    def diagnose_port(self, context, id, fields):
        return ports.diagnose_port(context, id, fields)

    @sessioned
    def get_route(self, context, id):
        return routes.get_route(context, id)

    @sessioned
    def get_routes(self, context):
        return routes.get_routes(context)

    @sessioned
    def create_route(self, context, route):
        self._fix_missing_tenant_id(context, route["route"])
        return routes.create_route(context, route)

    @sessioned
    def delete_route(self, context, id):
        routes.delete_route(context, id)

    @sessioned
    def create_subnet(self, context, subnet):
        self._fix_missing_tenant_id(context, subnet["subnet"])
        return subnets.create_subnet(context, subnet)

    @sessioned
    def update_subnet(self, context, id, subnet):
        return subnets.update_subnet(context, id, subnet)

    @sessioned
    def get_subnet(self, context, id, fields=None):
        return subnets.get_subnet(context, id, fields)

    @sessioned
    def get_subnets(self, context, filters=None, fields=None):
        return subnets.get_subnets(context, filters, fields)

    @sessioned
    def get_subnets_count(self, context, filters=None):
        return subnets.get_subnets_count(context, filters)

    @sessioned
    def delete_subnet(self, context, id):
        return subnets.delete_subnet(context, id)

    @sessioned
    def diagnose_subnet(self, context, id, fields):
        return subnets.diagnose_subnet(context, id, fields)

    @sessioned
    def create_network(self, context, network):
        self._fix_missing_tenant_id(context, network["network"])
        return networks.create_network(context, network)

    @sessioned
    def update_network(self, context, id, network):
        return networks.update_network(context, id, network)

    @sessioned
    def get_network(self, context, id, fields=None):
        return networks.get_network(context, id, fields)

    @sessioned
    def get_networks(self, context, filters=None, fields=None):
        return networks.get_networks(context, filters, fields)

    @sessioned
    def get_networks_count(self, context, filters=None):
        return networks.get_networks_count(context, filters)

    @sessioned
    def delete_network(self, context, id):
        return networks.delete_network(context, id)

    @sessioned
    def diagnose_network(self, context, id, fields):
        return networks.diagnose_network(context, id, fields)

    # NOTE(mdietz): we don't actually support these, but despite the fact that
    #               they're extensions in Neutron, Nova still expects to be
    #               able to call some of these as if they aren't
    def create_router(self, context, router):
        pass

    def update_router(self, context, id, router):
        pass

    def get_router(self, context, id, fields=None):
        pass

    def delete_router(self, context, id):
        pass

    def get_routers(self, context, filters=None, fields=None,
                    sorts=None, limit=None, marker=None, page_reverse=False):
        pass

    def add_router_interface(self, context, router_id, interface_info):
        pass

    def remove_router_interface(self, context, router_id, interface_info):
        pass

    def create_floatingip(self, context, floatingip):
        pass

    def update_floatingip(self, context, id, floatingip):
        pass

    def get_floatingip(self, context, id, fields=None):
        return None

    def delete_floatingip(self, context, id):
        pass

    def get_floatingips(self, context, filters=None, fields=None,
                        sorts=None, limit=None, marker=None,
                        page_reverse=False):
        return []

    def get_routers_count(self, context, filters=None):
        raise NotImplementedError()

    def get_floatingips_count(self, context, filters=None):
        raise NotImplementedError()
