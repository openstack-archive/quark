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

import netaddr
from neutron.common import config as neutron_cfg
from neutron.common import exceptions
from neutron.common import rpc as n_rpc
from neutron.openstack.common import importutils
from neutron.openstack.common import log as logging
from neutron.openstack.common import timeutils
from oslo.config import cfg

from quark import allocation_pool
from quark.db import api as db_api
from quark import exceptions as q_exc
from quark import network_strategy
from quark.plugin_modules import ip_policies
from quark.plugin_modules import routes
from quark import plugin_views as v
from quark import utils

CONF = cfg.CONF
LOG = logging.getLogger(__name__)
STRATEGY = network_strategy.STRATEGY

ipam_driver = (importutils.import_class(CONF.QUARK.ipam_driver))()


def _validate_subnet_cidr(context, network_id, new_subnet_cidr):
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


def create_subnet(context, subnet):
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

    with context.session.begin():
        net = db_api.network_find(context, id=net_id, scope=db_api.ONE)
        if not net:
            raise exceptions.NetworkNotFound(net_id=net_id)

        sub_attrs = subnet["subnet"]

        always_pop = ["enable_dhcp", "ip_version", "first_ip", "last_ip",
                      "_cidr"]
        admin_only = ["segment_id", "do_not_use", "created_at",
                      "next_auto_assign_ip"]
        utils.filter_body(context, sub_attrs, admin_only, always_pop)

        _validate_subnet_cidr(context, net_id, sub_attrs["cidr"])

        cidr = netaddr.IPNetwork(sub_attrs["cidr"])

        err_vals = {'cidr': sub_attrs["cidr"], 'network_id': net_id}
        err = _("Requested subnet with cidr: %(cidr)s for "
                "network: %(network_id)s. Prefix is too small, must be a "
                "larger subnet. A prefix less than /%(prefix)s is required.")

        if cidr.version == 6 and cidr.prefixlen > 64:
            err_vals["prefix"] = 65
            err_msg = err % err_vals
            raise exceptions.InvalidInput(error_message=err_msg)
        elif cidr.version == 4 and cidr.prefixlen > 30:
            err_vals["prefix"] = 31
            err_msg = err % err_vals
            raise exceptions.InvalidInput(error_message=err_msg)

        # See RM981. The default behavior of setting a gateway unless
        # explicitly asked to not is no longer desirable.
        gateway_ip = utils.pop_param(sub_attrs, "gateway_ip")
        dns_ips = utils.pop_param(sub_attrs, "dns_nameservers", [])
        host_routes = utils.pop_param(sub_attrs, "host_routes", [])
        allocation_pools = utils.pop_param(sub_attrs, "allocation_pools", None)

        sub_attrs["network"] = net
        new_subnet = db_api.subnet_create(context, **sub_attrs)

        cidrs = []
        alloc_pools = allocation_pool.AllocationPools(sub_attrs["cidr"],
                                                      allocation_pools)
        if isinstance(allocation_pools, list):
            cidrs = alloc_pools.get_policy_cidrs()

        ip_policies.ensure_default_policy(cidrs, [new_subnet])
        new_subnet["ip_policy"] = db_api.ip_policy_create(context,
                                                          exclude=cidrs)
        default_route = None
        for route in host_routes:
            netaddr_route = netaddr.IPNetwork(route["destination"])
            alloc_pools.validate_gateway_excluded(route["nexthop"])
            if netaddr_route.value == routes.DEFAULT_ROUTE.value:
                if default_route:
                    raise q_exc.DuplicateRouteConflict(
                        subnet_id=new_subnet["id"])

                default_route = route
                gateway_ip = default_route["nexthop"]
            new_subnet["routes"].append(db_api.route_create(
                context, cidr=route["destination"], gateway=route["nexthop"]))

        for dns_ip in dns_ips:
            new_subnet["dns_nameservers"].append(db_api.dns_create(
                context, ip=netaddr.IPAddress(dns_ip)))

        # if the gateway_ip is IN the cidr for the subnet and NOT excluded by
        # policies, we should raise a 409 conflict
        if gateway_ip and default_route is None:
            alloc_pools.validate_gateway_excluded(gateway_ip)
            new_subnet["routes"].append(db_api.route_create(
                context, cidr=str(routes.DEFAULT_ROUTE), gateway=gateway_ip))

    subnet_dict = v._make_subnet_dict(new_subnet)
    subnet_dict["gateway_ip"] = gateway_ip

    n_rpc.get_notifier("network").info(
        context,
        "ip_block.create",
        dict(tenant_id=subnet_dict["tenant_id"],
             ip_block_id=subnet_dict["id"],
             created_at=new_subnet["created_at"]))

    return subnet_dict


def update_subnet(context, id, subnet):
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

    with context.session.begin():
        subnet_db = db_api.subnet_find(context, id=id, scope=db_api.ONE)
        if not subnet_db:
            raise exceptions.SubnetNotFound(id=id)

        s = subnet["subnet"]
        always_pop = ["_cidr", "cidr", "first_ip", "last_ip", "ip_version",
                      "segment_id", "network_id"]
        admin_only = ["do_not_use", "created_at", "tenant_id",
                      "next_auto_assign_ip", "enable_dhcp"]
        utils.filter_body(context, s, admin_only, always_pop)

        dns_ips = utils.pop_param(s, "dns_nameservers", [])
        host_routes = utils.pop_param(s, "host_routes", [])
        gateway_ip = utils.pop_param(s, "gateway_ip", None)
        allocation_pools = utils.pop_param(s, "allocation_pools", None)

        alloc_pools = allocation_pool.AllocationPools(subnet_db["cidr"],
                                                      allocation_pools)

        if gateway_ip:
            alloc_pools.validate_gateway_excluded(gateway_ip)
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
            alloc_pools.validate_gateway_excluded(route["nexthop"])
            subnet_db["routes"].append(db_api.route_create(
                context, cidr=route["destination"], gateway=route["nexthop"]))

        if isinstance(allocation_pools, list):
            cidrs = alloc_pools.get_policy_cidrs()
            ip_policies.ensure_default_policy(cidrs, [subnet_db])
            subnet_db["ip_policy"] = db_api.ip_policy_update(
                context, subnet_db["ip_policy"], exclude=cidrs)

        subnet = db_api.subnet_update(context, subnet_db, **s)
    return v._make_subnet_dict(subnet)


def get_subnet(context, id, fields=None):
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
    subnet = db_api.subnet_find(context, id=id, join_dns=True,
                                join_routes=True, scope=db_api.ONE)
    if not subnet:
        raise exceptions.SubnetNotFound(subnet_id=id)

    # Check the network_id against the strategies
    net_id = subnet["network_id"]
    net_id = STRATEGY.get_parent_network(net_id)
    subnet["network_id"] = net_id

    return v._make_subnet_dict(subnet)


def get_subnets(context, filters=None, fields=None):
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
    subnets = db_api.subnet_find(context, join_dns=True, join_routes=True,
                                 **filters)
    return v._make_subnets_list(subnets, fields=fields)


def get_subnets_count(context, filters=None):
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


def _delete_subnet(context, subnet):
    if subnet.allocated_ips:
        raise exceptions.SubnetInUse(subnet_id=subnet["id"])
    db_api.subnet_delete(context, subnet)


def delete_subnet(context, id):
    """Delete a subnet.

    : param context: neutron api request context
    : param id: UUID representing the subnet to delete.
    """
    LOG.info("delete_subnet %s for tenant %s" % (id, context.tenant_id))
    with context.session.begin():
        subnet = db_api.subnet_find(context, id=id, scope=db_api.ONE)
        if not subnet:
            raise exceptions.SubnetNotFound(subnet_id=id)

        payload = dict(tenant_id=subnet["tenant_id"],
                       ip_block_id=subnet["id"],
                       created_at=subnet["created_at"],
                       deleted_at=timeutils.utcnow())

        _delete_subnet(context, subnet)

        n_rpc.get_notifier("network").info(context, "ip_block.delete", payload)


def diagnose_subnet(context, id, fields):
    if not context.is_admin:
        raise exceptions.NotAuthorized()

    if id == "*":
        return {'subnets': get_subnets(context, filters={})}
    return {'subnets': get_subnet(context, id)}
