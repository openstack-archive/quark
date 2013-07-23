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
from oslo.config import cfg

from sqlalchemy.orm import sessionmaker, scoped_session
from zope import sqlalchemy as zsa

from neutron.common import exceptions
from neutron.db import api as neutron_db_api
from neutron.extensions import providernet as pnet
from neutron.extensions import securitygroup as sg_ext
from neutron.openstack.common.db.sqlalchemy import session as neutron_session
from neutron.openstack.common import importutils
from neutron.openstack.common import log as logging
from neutron.openstack.common import uuidutils

from neutron import neutron_plugin_base_v2

from quark.api import extensions
from quark.db import api as db_api
from quark.db import models
from quark import network_strategy
from quark.plugin_modules import ip_addresses
from quark.plugin_modules import ip_policies
from quark.plugin_modules import mac_address_ranges
from quark.plugin_modules import ports
from quark.plugin_modules import routes
from quark.plugin_modules import security_groups
from quark.plugin_modules import subnets
from quark import plugin_views as v
from quark import utils

LOG = logging.getLogger("neutron.quark")
CONF = cfg.CONF
STRATEGY = network_strategy.STRATEGY


def append_quark_extensions(conf):
    """Adds the Quark API Extensions to the extension path.

    Pulled out for test coveage.
    """
    if 'api_extensions_path' in conf:
        conf.set_override('api_extensions_path', ":".join(extensions.__path__))

append_quark_extensions(CONF)


class Plugin(neutron_plugin_base_v2.NeutronPluginBaseV2,
             sg_ext.SecurityGroupPluginBase):
    supported_extension_aliases = ["mac_address_ranges", "routes",
                                   "ip_addresses", "ports_quark",
                                   "security-group",
                                   "subnets_quark", "provider",
                                   "ip_policies", "quotas"]

    def _initDBMaker(self):
        # This needs to be called after _ENGINE is configured
        session_maker = sessionmaker(bind=neutron_session._ENGINE,
                                     extension=zsa.ZopeTransactionExtension())
        neutron_session._MAKER = scoped_session(session_maker)

    def __init__(self):

        neutron_db_api.configure_db()
        self._initDBMaker()
        self.net_driver = (importutils.import_class(CONF.QUARK.net_driver))()
        self.net_driver.load_config(CONF.QUARK.net_driver_cfg)
        self.ipam_driver = (importutils.import_class(CONF.QUARK.ipam_driver))()
        self.ipam_reuse_after = CONF.QUARK.ipam_reuse_after
        neutron_db_api.register_models(base=models.BASEV2)

    def _adapt_provider_nets(self, context, network):
        #TODO(mdietz) going to ignore all the boundary and network
        #             type checking for now.
        attrs = network["network"]
        net_type = utils.pop_param(attrs, pnet.NETWORK_TYPE)
        phys_net = utils.pop_param(attrs, pnet.PHYSICAL_NETWORK)
        seg_id = utils.pop_param(attrs, pnet.SEGMENTATION_ID)
        return net_type, phys_net, seg_id

    def create_network(self, context, network):
        """Create a network.

        Create a network which represents an L2 network segment which
        can have a set of subnets and ports associated with it.
        : param context: neutron api request context
        : param network: dictionary describing the network, with keys
            as listed in the RESOURCE_ATTRIBUTE_MAP object in
            neutron/api/v2/attributes.py.  All keys will be populated.
        """
        LOG.info("create_network for tenant %s" % context.tenant_id)

        # Generate a uuid that we're going to hand to the backend and db
        net_uuid = uuidutils.generate_uuid()

        #TODO(mdietz) this will be the first component registry hook, but
        #             lets make it work first
        pnet_type, phys_net, seg_id = self._adapt_provider_nets(context,
                                                                network)
        net_attrs = network["network"]
        # NOTE(mdietz) I think ideally we would create the providernet
        # elsewhere as a separate driver step that could be
        # kept in a plugin and completely removed if desired. We could
        # have a pre-callback/observer on the netdriver create_network
        # that gathers any additional parameters from the network dict
        self.net_driver.create_network(context,
                                       net_attrs["name"],
                                       network_id=net_uuid,
                                       phys_type=pnet_type,
                                       phys_net=phys_net, segment_id=seg_id)

        subs = net_attrs.pop("subnets", [])

        net_attrs["id"] = net_uuid
        net_attrs["tenant_id"] = context.tenant_id
        new_net = db_api.network_create(context, **net_attrs)

        new_subnets = []
        for sub in subs:
            sub["subnet"]["network_id"] = new_net["id"]
            sub["subnet"]["tenant_id"] = context.tenant_id
            s = db_api.subnet_create(context, **sub["subnet"])
            new_subnets.append(s)
        new_net["subnets"] = new_subnets

        if not self.get_security_groups(
                context,
                filters={"id": security_groups.DEFAULT_SG_UUID}):
            security_groups._create_default_security_group(context)
        return v._make_network_dict(new_net)

    def update_network(self, context, id, network):
        """Update values of a network.

        : param context: neutron api request context
        : param id: UUID representing the network to update.
        : param network: dictionary with keys indicating fields to update.
            valid keys are those that have a value of True for 'allow_put'
            as listed in the RESOURCE_ATTRIBUTE_MAP object in
            neutron/api/v2/attributes.py.
        """
        LOG.info("update_network %s for tenant %s" %
                (id, context.tenant_id))
        net = db_api.network_find(context, id=id, scope=db_api.ONE)
        if not net:
            raise exceptions.NetworkNotFound(net_id=id)
        net = db_api.network_update(context, net, **network["network"])

        return v._make_network_dict(net)

    def get_network(self, context, id, fields=None):
        """Retrieve a network.

        : param context: neutron api request context
        : param id: UUID representing the network to fetch.
        : param fields: a list of strings that are valid keys in a
            network dictionary as listed in the RESOURCE_ATTRIBUTE_MAP
            object in neutron/api/v2/attributes.py. Only these fields
            will be returned.
        """
        LOG.info("get_network %s for tenant %s fields %s" %
                (id, context.tenant_id, fields))

        network = db_api.network_find(context, id=id, scope=db_api.ONE)

        if not network:
            raise exceptions.NetworkNotFound(net_id=id)
        return v._make_network_dict(network)

    def get_networks(self, context, filters=None, fields=None):
        """Retrieve a list of networks.

        The contents of the list depends on the identity of the user
        making the request (as indicated by the context) as well as any
        filters.
        : param context: neutron api request context
        : param filters: a dictionary with keys that are valid keys for
            a network as listed in the RESOURCE_ATTRIBUTE_MAP object
            in neutron/api/v2/attributes.py.  Values in this dictiontary
            are an iterable containing values that will be used for an exact
            match comparison for that value.  Each result returned by this
            function will have matched one of the values for each key in
            filters.
        : param fields: a list of strings that are valid keys in a
            network dictionary as listed in the RESOURCE_ATTRIBUTE_MAP
            object in neutron/api/v2/attributes.py. Only these fields
            will be returned.
        """
        LOG.info("get_networks for tenant %s with filters %s, fields %s" %
                (context.tenant_id, filters, fields))
        nets = db_api.network_find(context, **filters)
        return [v._make_network_dict(net) for net in nets]

    def get_networks_count(self, context, filters=None):
        """Return the number of networks.

        The result depends on the identity of the user making the request
        (as indicated by the context) as well as any filters.
        : param context: neutron api request context
        : param filters: a dictionary with keys that are valid keys for
            a network as listed in the RESOURCE_ATTRIBUTE_MAP object
            in neutron/api/v2/attributes.py.  Values in this dictiontary
            are an iterable containing values that will be used for an exact
            match comparison for that value.  Each result returned by this
            function will have matched one of the values for each key in
            filters.

        NOTE: this method is optional, as it was not part of the originally
              defined plugin API.
        """
        LOG.info("get_networks_count for tenant %s filters %s" %
                (context.tenant_id, filters))
        return db_api.network_count_all(context)

    def delete_network(self, context, id):
        """Delete a network.

        : param context: neutron api request context
        : param id: UUID representing the network to delete.
        """
        LOG.info("delete_network %s for tenant %s" % (id, context.tenant_id))
        net = db_api.network_find(context, id=id, scope=db_api.ONE)
        if not net:
            raise exceptions.NetworkNotFound(net_id=id)
        if net.ports:
            raise exceptions.NetworkInUse(net_id=id)
        self.net_driver.delete_network(context, id)
        for subnet in net["subnets"]:
            subnets._delete_subnet(context, subnet)
        db_api.network_delete(context, net)

    def get_mac_address_range(self, context, id, fields=None):
        return mac_address_ranges.get_mac_address_range(context, id, fields)

    def get_mac_address_ranges(self, context):
        return mac_address_ranges.get_mac_address_ranges(context)

    def create_mac_address_range(self, context, mac_range):
        return mac_address_ranges.create_mac_address_range(context, mac_range)

    def delete_mac_address_range(self, context, id):
        mac_address_ranges.delete_mac_address_range(context, id)

    def create_security_group(self, context, security_group):
        return security_groups.create_security_group(context, security_group)

    def create_security_group_rule(self, context, security_group_rule):
        return security_groups.create_security_group_rule(context,
                                                          security_group_rule)

    def delete_security_group(self, context, id):
        security_groups.delete_security_group(context, id)

    def delete_security_group_rule(self, context, id):
        security_groups.delete_security_group_rule(context, id)

    def get_security_group(self, context, id, fields=None):
        return security_groups.get_security_group(context, id, fields)

    def get_security_group_rule(self, context, id, fields=None):
        return security_groups.get_security_group_rule(context, id, fields)

    def get_security_groups(self, context, filters=None, fields=None,
                            sorts=None, limit=None, marker=None,
                            page_reverse=False):
        return security_groups.get_security_groups(context, filters, fields,
                                                   sorts, limit, marker,
                                                   page_reverse)

    def get_security_group_rules(self, context, filters=None, fields=None,
                                 sorts=None, limit=None, marker=None,
                                 page_reverse=False):
        return security_groups.get_security_group_rules(context, filters,
                                                        fields, sorts, limit,
                                                        marker, page_reverse)

    def update_security_group(self, context, id, security_group):
        return security_groups.update_security_group(context, id,
                                                     security_group)

    def create_ip_policy(self, context, ip_policy):
        return ip_policies.create_ip_policy(context, ip_policy)

    def get_ip_policy(self, context, id):
        return ip_policies.get_ip_policy(context, id)

    def get_ip_policies(self, context, **filters):
        return ip_policies.get_ip_policies(context, **filters)

    def delete_ip_policy(self, context, id):
        return ip_policies.delete_ip_policy(context, id)

    def get_ip_addresses(self, context, **filters):
        return ip_addresses.get_ip_addresses(context, **filters)

    def get_ip_address(self, context, id):
        return ip_addresses.get_ip_address(context, id)

    def create_ip_address(self, context, ip_address):
        return ip_addresses.create_ip_address(context, ip_address)

    def update_ip_address(self, context, id, ip_address):
        return ip_addresses.update_ip_address(context, id, ip_address)

    def create_port(self, context, port):
        return ports.create_port(context, port)

    def post_update_port(self, context, id, port):
        return ports.post_update_port(context, id, port)

    def get_port(self, context, id, fields=None):
        return ports.get_port(context, id, fields)

    def update_port(self, context, id, port):
        return ports.update_port(context, id, port)

    def get_ports(self, context, filters=None, fields=None):
        return ports.get_ports(context, filters, fields)

    def get_ports_count(self, context, filters=None):
        return ports.get_ports_count(context, filters)

    def delete_port(self, context, id):
        return ports.delete_port(context, id)

    def disassociate_port(self, context, id, ip_address_id):
        return ports.disassociate_port(context, id, ip_address_id)

    def get_route(self, context, id):
        return routes.get_route(context, id)

    def get_routes(self, context):
        return routes.get_routes(context)

    def create_route(self, context, route):
        return routes.create_route(context, route)

    def delete_route(self, context, id):
        routes.delete_route(context, id)

    def create_subnet(self, context, subnet):
        return subnets.create_subnet(context, subnet)

    def update_subnet(self, context, id, subnet):
        return subnets.update_subnet(context, id, subnet)

    def get_subnet(self, context, id, fields=None):
        return subnets.get_subnet(context, id, fields)

    def get_subnets(self, context, filters=None, fields=None):
        return subnets.get_subnets(context, filters, fields)

    def get_subnets_count(self, context, filters=None):
        return subnets.get_subnets_count(context, filters)

    def delete_subnet(self, context, id):
        return subnets.delete_subnet(context, id)
