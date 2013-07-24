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
import netaddr
from oslo.config import cfg

from sqlalchemy.orm import sessionmaker, scoped_session
from zope import sqlalchemy as zsa

#FIXME(mdietz): remove once all resources have moved into submods
from neutron.common import config as neutron_cfg
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

    def _validate_subnet_cidr(self, context, network_id, new_subnet_cidr):
        """Validate the CIDR for a subnet.

        Verifies the specified CIDR does not overlap with the ones defined
        for the other subnets specified for this network, or with any other
        CIDR if overlapping IPs are disabled.

        """
        if neutron_cfg.cfg.CONF.allow_overlapping_ips:
            return

        new_subnet_ipset = netaddr.IPSet([new_subnet_cidr])

        # Using admin context here, in case we actually share networks later
        subnet_list = db_api.subnet_find(context.elevated(),
                                         network_id=network_id)
        for subnet in subnet_list:
            if (netaddr.IPSet([subnet.cidr]) & new_subnet_ipset):
                # don't give out details of the overlapping subnet
                err_msg = (_("Requested subnet with cidr: %(cidr)s for "
                             "network: %(network_id)s overlaps with another "
                             "subnet") %
                           {'cidr': new_subnet_cidr,
                            'network_id': network_id})
                LOG.error(_("Validation for CIDR: %(new_cidr)s failed - "
                            "overlaps with subnet %(subnet_id)s "
                            "(CIDR: %(cidr)s)"),
                          {'new_cidr': new_subnet_cidr,
                           'subnet_id': subnet.id,
                           'cidr': subnet.cidr})
                raise exceptions.InvalidInput(error_message=err_msg)

    def create_subnet(self, context, subnet):
        """Create a subnet.

        Create a subnet which represents a range of IP addresses
        that can be allocated to devices

        : param context: neutron api request context
        : param subnet: dictionary describing the subnet, with keys
            as listed in the RESOURCE_ATTRIBUTE_MAP object in
            neutron/api/v2/attributes.py.  All keys will be populated.
        """
        LOG.info("create_subnet for tenant %s" % context.tenant_id)
        net_id = subnet["subnet"]["network_id"]

        net = db_api.network_find(context, id=net_id, scope=db_api.ONE)
        if not net:
            raise exceptions.NetworkNotFound(net_id=net_id)

        sub_attrs = subnet["subnet"]

        self._validate_subnet_cidr(context, net_id, sub_attrs["cidr"])

        cidr = netaddr.IPNetwork(sub_attrs["cidr"])
        gateway_ip = utils.pop_param(sub_attrs, "gateway_ip", str(cidr[1]))
        dns_ips = utils.pop_param(sub_attrs, "dns_nameservers", [])
        host_routes = utils.pop_param(sub_attrs, "host_routes", [])
        allocation_pools = utils.pop_param(sub_attrs, "allocation_pools", [])

        new_subnet = db_api.subnet_create(context, **sub_attrs)

        default_route = None
        for route in host_routes:
            netaddr_route = netaddr.IPNetwork(route["destination"])
            if netaddr_route.value == routes.DEFAULT_ROUTE.value:
                default_route = route
                gateway_ip = default_route["nexthop"]
            new_subnet["routes"].append(db_api.route_create(
                context, cidr=route["destination"], gateway=route["nexthop"]))

        if default_route is None:
            new_subnet["routes"].append(db_api.route_create(
                context, cidr=str(routes.DEFAULT_ROUTE), gateway=gateway_ip))

        for dns_ip in dns_ips:
            new_subnet["dns_nameservers"].append(db_api.dns_create(
                context, ip=netaddr.IPAddress(dns_ip)))

        if allocation_pools:
            exclude = netaddr.IPSet([cidr])
            for p in allocation_pools:
                x = netaddr.IPSet(netaddr.IPRange(p["start"], p["end"]))
                exclude = exclude - x
            new_subnet["ip_policy"] = db_api.ip_policy_create(context,
                                                              exclude=exclude)
        # HACK(amir): force backref for ip_policy
        if not new_subnet["network"]:
            new_subnet["network"] = net
        subnet_dict = v._make_subnet_dict(new_subnet,
                                          default_route=routes.DEFAULT_ROUTE)
        subnet_dict["gateway_ip"] = gateway_ip
        return subnet_dict

    def update_subnet(self, context, id, subnet):
        """Update values of a subnet.

        : param context: neutron api request context
        : param id: UUID representing the subnet to update.
        : param subnet: dictionary with keys indicating fields to update.
            valid keys are those that have a value of True for 'allow_put'
            as listed in the RESOURCE_ATTRIBUTE_MAP object in
            neutron/api/v2/attributes.py.
        """
        LOG.info("update_subnet %s for tenant %s" %
                 (id, context.tenant_id))

        subnet_db = db_api.subnet_find(context, id=id, scope=db_api.ONE)
        if not subnet_db:
            raise exceptions.SubnetNotFound(id=id)

        s = subnet["subnet"]

        dns_ips = s.pop("dns_nameservers", [])
        host_routes = s.pop("host_routes", [])
        gateway_ip = s.pop("gateway_ip", None)

        if gateway_ip:
            default_route = None
            for route in host_routes:
                netaddr_route = netaddr.IPNetwork(route["destination"])
                if netaddr_route.value == routes.DEFAULT_ROUTE.value:
                    default_route = route
                    break
            if default_route is None:
                route_model = db_api.route_find(
                    context, cidr=str(routes.DEFAULT_ROUTE), subnet_id=id,
                    scope=db_api.ONE)
                if route_model:
                    db_api.route_update(context, route_model,
                                        gateway=gateway_ip)
                else:
                    db_api.route_create(context,
                                        cidr=str(routes.DEFAULT_ROUTE),
                                        gateway=gateway_ip, subnet_id=id)

        if dns_ips:
            subnet_db["dns_nameservers"] = []
        for dns_ip in dns_ips:
            subnet_db["dns_nameservers"].append(db_api.dns_create(
                context,
                ip=netaddr.IPAddress(dns_ip)))

        if host_routes:
            subnet_db["routes"] = []
        for route in host_routes:
            subnet_db["routes"].append(db_api.route_create(
                context, cidr=route["destination"], gateway=route["nexthop"]))

        subnet = db_api.subnet_update(context, subnet_db, **s)
        return v._make_subnet_dict(subnet, default_route=routes.DEFAULT_ROUTE)

    def get_subnet(self, context, id, fields=None):
        """Retrieve a subnet.

        : param context: neutron api request context
        : param id: UUID representing the subnet to fetch.
        : param fields: a list of strings that are valid keys in a
            subnet dictionary as listed in the RESOURCE_ATTRIBUTE_MAP
            object in neutron/api/v2/attributes.py. Only these fields
            will be returned.
        """
        LOG.info("get_subnet %s for tenant %s with fields %s" %
                (id, context.tenant_id, fields))
        subnet = db_api.subnet_find(context, id=id, scope=db_api.ONE)
        if not subnet:
            raise exceptions.SubnetNotFound(subnet_id=id)

        # Check the network_id against the strategies
        net_id = subnet["network_id"]
        net_id = STRATEGY.get_parent_network(net_id)
        subnet["network_id"] = net_id

        return v._make_subnet_dict(subnet, default_route=routes.DEFAULT_ROUTE)

    def get_subnets(self, context, filters=None, fields=None):
        """Retrieve a list of subnets.

        The contents of the list depends on the identity of the user
        making the request (as indicated by the context) as well as any
        filters.
        : param context: neutron api request context
        : param filters: a dictionary with keys that are valid keys for
            a subnet as listed in the RESOURCE_ATTRIBUTE_MAP object
            in neutron/api/v2/attributes.py.  Values in this dictiontary
            are an iterable containing values that will be used for an exact
            match comparison for that value.  Each result returned by this
            function will have matched one of the values for each key in
            filters.
        : param fields: a list of strings that are valid keys in a
            subnet dictionary as listed in the RESOURCE_ATTRIBUTE_MAP
            object in neutron/api/v2/attributes.py. Only these fields
            will be returned.
        """
        LOG.info("get_subnets for tenant %s with filters %s fields %s" %
                (context.tenant_id, filters, fields))
        subnets = db_api.subnet_find(context, **filters)
        return v._make_subnets_list(subnets, fields=fields,
                                    default_route=routes.DEFAULT_ROUTE)

    def get_subnets_count(self, context, filters=None):
        """Return the number of subnets.

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
        LOG.info("get_subnets_count for tenant %s with filters %s" %
                (context.tenant_id, filters))
        return db_api.subnet_count_all(context, **filters)

    def _delete_subnet(self, context, subnet):
        if subnet.allocated_ips:
            raise exceptions.SubnetInUse(subnet_id=subnet["id"])
        db_api.subnet_delete(context, subnet)

    def delete_subnet(self, context, id):
        """Delete a subnet.

        : param context: neutron api request context
        : param id: UUID representing the subnet to delete.
        """
        LOG.info("delete_subnet %s for tenant %s" % (id, context.tenant_id))
        subnet = db_api.subnet_find(context, id=id, scope=db_api.ONE)
        if not subnet:
            raise exceptions.SubnetNotFound(subnet_id=id)
        self._delete_subnet(context, subnet)

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

        subnets = net_attrs.pop("subnets", [])

        net_attrs["id"] = net_uuid
        net_attrs["tenant_id"] = context.tenant_id
        new_net = db_api.network_create(context, **net_attrs)

        new_subnets = []
        for sub in subnets:
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
            self._delete_subnet(context, subnet)
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
