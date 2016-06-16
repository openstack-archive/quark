# Copyright 2013 Rackspace Hosting Inc.
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
from neutron.common import rpc as n_rpc
from neutron import quota
from neutron_lib import exceptions as n_exc
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import importutils
from oslo_utils import timeutils

from quark import allocation_pool
from quark.db import api as db_api
from quark import exceptions as q_exc
from quark import network_strategy
from quark.plugin_modules import ip_policies
from quark.plugin_modules import routes
from quark import plugin_views as v
from quark import quota_driver as qdv
from quark import utils

CONF = cfg.CONF
LOG = logging.getLogger(__name__)
STRATEGY = network_strategy.STRATEGY

quark_subnet_opts = [
    cfg.BoolOpt('allow_allocation_pool_update',
                default=False,
                help=_('Controls whether or not to allow allocation_pool '
                       'updates')),
    cfg.BoolOpt('allow_allocation_pool_growth',
                default=False,
                help=_('Controls whether or not to allow allocation_pool '
                       'growing. Otherwise shrinking is only allowed'))
]

CONF.register_opts(quark_subnet_opts, "QUARK")

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
    subnet_list = db_api.subnet_find(context.elevated(), None, None, None,
                                     False, network_id=network_id,
                                     shared=[False])
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
            raise n_exc.InvalidInput(error_message=err_msg)


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
        net = db_api.network_find(context, None, None, None, False,
                                  id=net_id, scope=db_api.ONE)
        if not net:
            raise n_exc.NetworkNotFound(net_id=net_id)

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
            raise n_exc.InvalidInput(error_message=err_msg)
        elif cidr.version == 4 and cidr.prefixlen > 30:
            err_vals["prefix"] = 31
            err_msg = err % err_vals
            raise n_exc.InvalidInput(error_message=err_msg)
        # Enforce subnet quotas
        net_subnets = get_subnets(context,
                                  filters=dict(network_id=net_id))
        if not context.is_admin:
            v4_count, v6_count = 0, 0
            for subnet in net_subnets:
                if netaddr.IPNetwork(subnet['cidr']).version == 6:
                    v6_count += 1
                else:
                    v4_count += 1

            if cidr.version == 6:
                tenant_quota_v6 = context.session.query(qdv.Quota).filter_by(
                    tenant_id=context.tenant_id,
                    resource='v6_subnets_per_network').first()
                if tenant_quota_v6 != -1:
                    quota.QUOTAS.limit_check(
                        context, context.tenant_id,
                        v6_subnets_per_network=v6_count + 1)
            else:
                tenant_quota_v4 = context.session.query(qdv.Quota).filter_by(
                    tenant_id=context.tenant_id,
                    resource='v4_subnets_per_network').first()
                if tenant_quota_v4 != -1:
                    quota.QUOTAS.limit_check(
                        context, context.tenant_id,
                        v4_subnets_per_network=v4_count + 1)

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

        quota.QUOTAS.limit_check(
            context,
            context.tenant_id,
            alloc_pools_per_subnet=len(alloc_pools))

        ip_policies.ensure_default_policy(cidrs, [new_subnet])
        new_subnet["ip_policy"] = db_api.ip_policy_create(context,
                                                          exclude=cidrs)

        quota.QUOTAS.limit_check(context, context.tenant_id,
                                 routes_per_subnet=len(host_routes))

        default_route = None
        for route in host_routes:
            netaddr_route = netaddr.IPNetwork(route["destination"])
            if netaddr_route.value == routes.DEFAULT_ROUTE.value:
                if default_route:
                    raise q_exc.DuplicateRouteConflict(
                        subnet_id=new_subnet["id"])

                default_route = route
                gateway_ip = default_route["nexthop"]
                alloc_pools.validate_gateway_excluded(gateway_ip)

            new_subnet["routes"].append(db_api.route_create(
                context, cidr=route["destination"], gateway=route["nexthop"]))

        quota.QUOTAS.limit_check(context, context.tenant_id,
                                 dns_nameservers_per_subnet=len(dns_ips))

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


def _pool_is_growing(original_pool, new_pool):
    # create IPSet for original pool
    ori_set = netaddr.IPSet()
    for rng in original_pool._alloc_pools:
        ori_set.add(netaddr.IPRange(rng['start'], rng['end']))

    # create IPSet for net pool
    new_set = netaddr.IPSet()
    for rng in new_pool._alloc_pools:
        new_set.add(netaddr.IPRange(rng['start'], rng['end']))

    # we are growing the original set is not a superset of the new set
    return not ori_set.issuperset(new_set)


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
        subnet_db = db_api.subnet_find(context, None, None, None, False, id=id,
                                       scope=db_api.ONE)
        if not subnet_db:
            raise n_exc.SubnetNotFound(subnet_id=id)

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
        if not CONF.QUARK.allow_allocation_pool_update:
            if allocation_pools:
                raise n_exc.BadRequest(
                    resource="subnets",
                    msg="Allocation pools cannot be updated.")

            if subnet_db["ip_policy"] is not None:
                ip_policy_cidrs = subnet_db["ip_policy"].get_cidrs_ip_set()
            else:
                ip_policy_cidrs = netaddr.IPSet([])

            alloc_pools = allocation_pool.AllocationPools(
                subnet_db["cidr"],
                policies=ip_policy_cidrs)
        else:
            alloc_pools = allocation_pool.AllocationPools(subnet_db["cidr"],
                                                          allocation_pools)
            original_pools = subnet_db.allocation_pools
            ori_pools = allocation_pool.AllocationPools(subnet_db["cidr"],
                                                        original_pools)
            # Check if the pools are growing or shrinking
            is_growing = _pool_is_growing(ori_pools, alloc_pools)
            if not CONF.QUARK.allow_allocation_pool_growth and is_growing:
                raise n_exc.BadRequest(
                    resource="subnets",
                    msg="Allocation pools may not be updated to be larger "
                        "do to configuration settings")

        quota.QUOTAS.limit_check(
            context,
            context.tenant_id,
            alloc_pools_per_subnet=len(alloc_pools))
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
            quota.QUOTAS.limit_check(context, context.tenant_id,
                                     dns_nameservers_per_subnet=len(dns_ips))

        for dns_ip in dns_ips:
            subnet_db["dns_nameservers"].append(db_api.dns_create(
                context,
                ip=netaddr.IPAddress(dns_ip)))

        if host_routes:
            subnet_db["routes"] = []
            quota.QUOTAS.limit_check(context, context.tenant_id,
                                     routes_per_subnet=len(host_routes))

        for route in host_routes:
            subnet_db["routes"].append(db_api.route_create(
                context, cidr=route["destination"], gateway=route["nexthop"]))
        if CONF.QUARK.allow_allocation_pool_update:
            if isinstance(allocation_pools, list):
                cidrs = alloc_pools.get_policy_cidrs()
                ip_policies.ensure_default_policy(cidrs, [subnet_db])
                subnet_db["ip_policy"] = db_api.ip_policy_update(
                    context, subnet_db["ip_policy"], exclude=cidrs)
                # invalidate the cache
                db_api.subnet_update_set_alloc_pool_cache(context, subnet_db)
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
    subnet = db_api.subnet_find(context, None, None, None, False, id=id,
                                join_dns=True, join_routes=True,
                                scope=db_api.ONE)
    if not subnet:
        raise n_exc.SubnetNotFound(subnet_id=id)

    cache = subnet.get("_allocation_pool_cache")
    if not cache:
        new_cache = subnet.allocation_pools
        db_api.subnet_update_set_alloc_pool_cache(context, subnet, new_cache)
    return v._make_subnet_dict(subnet)


def get_subnets(context, limit=None, page_reverse=False, sorts=None,
                marker=None, filters=None, fields=None):
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
    filters = filters or {}
    subnets = db_api.subnet_find(context, limit=limit,
                                 page_reverse=page_reverse, sorts=sorts,
                                 marker_obj=marker, join_dns=True,
                                 join_routes=True, join_pool=True, **filters)
    for subnet in subnets:
        cache = subnet.get("_allocation_pool_cache")
        if not cache:
            db_api.subnet_update_set_alloc_pool_cache(
                context, subnet, subnet.allocation_pools)
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
        raise n_exc.SubnetInUse(subnet_id=subnet["id"])
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
            raise n_exc.SubnetNotFound(subnet_id=id)

        payload = dict(tenant_id=subnet["tenant_id"],
                       ip_block_id=subnet["id"],
                       created_at=subnet["created_at"],
                       deleted_at=timeutils.utcnow())

        _delete_subnet(context, subnet)

        n_rpc.get_notifier("network").info(context, "ip_block.delete", payload)


def diagnose_subnet(context, id, fields):
    if not context.is_admin:
        raise n_exc.NotAuthorized()

    if id == "*":
        return {'subnets': get_subnets(context, filters={})}
    return {'subnets': get_subnet(context, id)}
