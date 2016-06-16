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
from neutron_lib import exceptions as n_exc
from oslo_config import cfg
from oslo_log import log as logging

from quark import allocation_pool
from quark.db import api as db_api
from quark import exceptions as q_exc
from quark import plugin_views as v

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


def _validate_policy_with_routes(context, policies, subnets):
    pools = {}
    policy_networks = [netaddr.IPNetwork(p) for p in policies]
    for subnet in subnets:
        pool = allocation_pool.AllocationPools(subnet["cidr"],
                                               policies=policy_networks)
        pools[subnet["id"]] = pool

    subnet_ids = [subnet["id"] for subnet in subnets]

    routes = db_api.route_find(context, subnet_id=subnet_ids)
    for route in routes:
        subnet_pool = pools[route["subnet_id"]]
        subnet_pool.validate_gateway_excluded(route["gateway"])


def create_ip_policy(context, ip_policy):
    LOG.info("create_ip_policy for tenant %s" % context.tenant_id)

    ipp = ip_policy['ip_policy']

    if not ipp.get("exclude"):
        raise n_exc.BadRequest(resource="ip_policy",
                               msg="Empty ip_policy.exclude")

    network_ids = ipp.get("network_ids")
    subnet_ids = ipp.get("subnet_ids")

    if subnet_ids and network_ids:
        raise n_exc.BadRequest(
            resource="ip_policy",
            msg="network_ids and subnet_ids specified. only one allowed")

    if not subnet_ids and not network_ids:
        raise n_exc.BadRequest(
            resource="ip_policy",
            msg="network_ids or subnet_ids not specified")

    with context.session.begin():
        if subnet_ids:
            subnets = db_api.subnet_find(
                context, id=subnet_ids, scope=db_api.ALL)
            if not subnets:
                raise n_exc.SubnetNotFound(subnet_id=subnet_ids)
            _check_for_pre_existing_policies_in(subnets)
            ensure_default_policy(ipp["exclude"], subnets)
            _validate_cidrs_fit_into_subnets(ipp["exclude"], subnets)
            ipp.pop("subnet_ids")
            ipp["subnets"] = subnets

        if network_ids:
            nets = db_api.network_find(
                context, id=network_ids, scope=db_api.ALL)
            if not nets:
                raise n_exc.NetworkNotFound(net_id=network_ids)
            _check_for_pre_existing_policies_in(nets)
            subnets = [subnet for net in nets
                       for subnet in net.get("subnets", [])]
            ensure_default_policy(ipp["exclude"], subnets)
            _validate_cidrs_fit_into_subnets(ipp["exclude"], subnets)
            ipp.pop("network_ids")
            ipp["networks"] = nets

        ip_policy = db_api.ip_policy_create(context, **ipp)
    return v._make_ip_policy_dict(ip_policy)


def _check_for_pre_existing_policies_in(models):
    models_with_existing_policies = [model for model in models
                                     if model.get('ip_policy', None)]
    if models_with_existing_policies:
        first_model = models_with_existing_policies[0]
        raise q_exc.IPPolicyAlreadyExists(
            id=first_model['ip_policy']['id'],
            n_id=first_model['id'])


def get_ip_policy(context, id):
    LOG.info("get_ip_policy %s for tenant %s" % (id, context.tenant_id))
    ipp = db_api.ip_policy_find(context, id=id, scope=db_api.ONE)
    if not ipp:
        raise q_exc.IPPolicyNotFound(id=id)
    return v._make_ip_policy_dict(ipp)


def get_ip_policies(context, **filters):
    LOG.info("get_ip_policies for tenant %s" % (context.tenant_id))
    ipps = db_api.ip_policy_find(context, scope=db_api.ALL, **filters)
    return [v._make_ip_policy_dict(ipp) for ipp in ipps]


def update_ip_policy(context, id, ip_policy):
    LOG.info("update_ip_policy for tenant %s" % context.tenant_id)

    ipp = ip_policy["ip_policy"]

    with context.session.begin():
        ipp_db = db_api.ip_policy_find(context, id=id, scope=db_api.ONE)
        if not ipp_db:
            raise q_exc.IPPolicyNotFound(id=id)

        ip_policy_cidrs = ipp.get("exclude")
        network_ids = ipp.get("network_ids")
        subnet_ids = ipp.get("subnet_ids")

        if subnet_ids and network_ids:
            raise n_exc.BadRequest(
                resource="ip_policy",
                msg="network_ids and subnet_ids specified. only one allowed")

        models = []
        all_subnets = []
        if subnet_ids:
            for subnet in ipp_db["subnets"]:
                subnet["ip_policy"] = None
            subnets = db_api.subnet_find(
                context, id=subnet_ids, scope=db_api.ALL)
            if len(subnets) != len(subnet_ids):
                raise n_exc.SubnetNotFound(subnet_id=subnet_ids)
            if ip_policy_cidrs is not None:
                ensure_default_policy(ip_policy_cidrs, subnets)
                _validate_cidrs_fit_into_subnets(ip_policy_cidrs, subnets)
            all_subnets.extend(subnets)
            models.extend(subnets)

        if network_ids:
            for network in ipp_db["networks"]:
                network["ip_policy"] = None
            nets = db_api.network_find(context, id=network_ids,
                                       scope=db_api.ALL)
            if len(nets) != len(network_ids):
                raise n_exc.NetworkNotFound(net_id=network_ids)
            subnets = [subnet for net in nets
                       for subnet in net.get("subnets", [])]
            if ip_policy_cidrs is not None:
                ensure_default_policy(ip_policy_cidrs, subnets)
                _validate_cidrs_fit_into_subnets(ip_policy_cidrs, subnets)
            all_subnets.extend(subnets)
            models.extend(nets)

        if not subnet_ids and not network_ids and ip_policy_cidrs is not None:
            ensure_default_policy(ip_policy_cidrs, ipp_db["subnets"])
            _validate_cidrs_fit_into_subnets(
                ip_policy_cidrs, ipp_db["subnets"])

        for model in models:
            if model["ip_policy"]:
                raise q_exc.IPPolicyAlreadyExists(
                    id=model["ip_policy"]["id"], n_id=model["id"])
            model["ip_policy"] = ipp_db

        if ip_policy_cidrs:
            _validate_policy_with_routes(context, ip_policy_cidrs, all_subnets)
        ipp_db = db_api.ip_policy_update(context, ipp_db, **ipp)
    return v._make_ip_policy_dict(ipp_db)


def delete_ip_policy(context, id):
    LOG.info("delete_ip_policy %s for tenant %s" % (id, context.tenant_id))
    with context.session.begin():
        ipp = db_api.ip_policy_find(context, id=id, scope=db_api.ONE)
        if not ipp:
            raise q_exc.IPPolicyNotFound(id=id)
        if ipp["networks"] or ipp["subnets"]:
            raise q_exc.IPPolicyInUse(id=id)
        db_api.ip_policy_delete(context, ipp)


def _validate_cidrs_fit_into_subnets(cidrs, subnets):
    LOG.info("validate_cidrs_all_fit_into_subnets with CIDRs (%s) "
             "and subnets (%s)" % (cidrs, subnets))
    for cidr in cidrs:
        cidr = netaddr.IPNetwork(cidr)
        for subnet in subnets:
            subnet_cidr = netaddr.IPNetwork(subnet["cidr"])
            if cidr.version == subnet_cidr.version and cidr not in subnet_cidr:
                raise n_exc.BadRequest(
                    resource="ip_policy",
                    msg="CIDR %s not in subnet CIDR %s"
                    % (cidr, subnet_cidr))


def ensure_default_policy(cidrs, subnets):
    policy_cidrs = netaddr.IPSet(cidrs)
    for subnet in subnets:
        subnet_cidr = netaddr.IPNetwork(subnet["cidr"])
        network_ip = subnet_cidr.network
        broadcast_ip = subnet_cidr.broadcast
        prefix_len = '32' if subnet_cidr.version == 4 else '128'
        default_policy_cidrs = ["%s/%s" % (network_ip, prefix_len),
                                "%s/%s" % (broadcast_ip, prefix_len)]
        for cidr in default_policy_cidrs:
            if (netaddr.IPNetwork(cidr) not in policy_cidrs
                    and cidr not in cidrs):
                cidrs.append(cidr)
