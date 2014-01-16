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

from neutron.common import exceptions
from neutron.openstack.common import log as logging
from oslo.config import cfg

from quark.db import api as db_api
from quark import exceptions as quark_exceptions
from quark import plugin_views as v

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


def create_ip_policy(context, ip_policy):
    LOG.info("create_ip_policy for tenant %s" % context.tenant_id)

    ipp = ip_policy['ip_policy']

    if not ipp.get("exclude"):
        raise exceptions.BadRequest(resource="ip_policy",
                                    msg="Empty ip_policy.exclude regions")

    network_ids = ipp.get("network_ids")
    subnet_ids = ipp.get("subnet_ids")

    if not subnet_ids and not network_ids:
        raise exceptions.BadRequest(
            resource="ip_policy",
            msg="network_ids or subnet_ids not specified")

    with context.session.begin():
        models = []
        if subnet_ids:
            subnets = db_api.subnet_find(
                context, id=subnet_ids, scope=db_api.ALL)
            if not subnets:
                raise exceptions.SubnetNotFound(id=subnet_ids)
            models.extend(subnets)

        if network_ids:
            nets = db_api.network_find(
                context, id=network_ids, scope=db_api.ALL)
            if not nets:
                raise exceptions.NetworkNotFound(net_id=network_ids)
            models.extend(nets)

        for model in models:
            if model["ip_policy"]:
                raise quark_exceptions.IPPolicyAlreadyExists(
                    id=model["ip_policy"]["id"], n_id=model["id"])
            model["ip_policy"] = db_api.ip_policy_create(context, **ipp)

    return v._make_ip_policy_dict(model["ip_policy"])


def get_ip_policy(context, id):
    LOG.info("get_ip_policy %s for tenant %s" % (id, context.tenant_id))
    ipp = db_api.ip_policy_find(context, id=id, scope=db_api.ONE)
    if not ipp:
        raise quark_exceptions.IPPolicyNotFound(id=id)
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
            raise quark_exceptions.IPPolicyNotFound(id=id)

        network_ids = ipp.get("network_ids")
        subnet_ids = ipp.get("subnet_ids")

        models = []
        if subnet_ids:
            for subnet in ipp_db["subnets"]:
                subnet["ip_policy"] = None
            subnets = db_api.subnet_find(
                context, id=subnet_ids, scope=db_api.ALL)
            if len(subnets) != len(subnet_ids):
                raise exceptions.SubnetNotFound(id=subnet_ids)
            models.extend(subnets)

        if network_ids:
            for network in ipp_db["networks"]:
                network["ip_policy"] = None
            nets = db_api.network_find(context, id=network_ids,
                                       scope=db_api.ALL)
            if len(nets) != len(network_ids):
                raise exceptions.NetworkNotFound(net_id=network_ids)
            models.extend(nets)

        for model in models:
            if model["ip_policy"]:
                raise quark_exceptions.IPPolicyAlreadyExists(
                    id=model["ip_policy"]["id"], n_id=model["id"])
            model["ip_policy"] = ipp_db

        ipp_db = db_api.ip_policy_update(context, ipp_db, **ipp)
    return v._make_ip_policy_dict(ipp_db)


def delete_ip_policy(context, id):
    LOG.info("delete_ip_policy %s for tenant %s" % (id, context.tenant_id))
    with context.session.begin():
        ipp = db_api.ip_policy_find(context, id=id, scope=db_api.ONE)
        if not ipp:
            raise quark_exceptions.IPPolicyNotFound(id=id)
        if ipp["networks"] or ipp["subnets"]:
            raise quark_exceptions.IPPolicyInUse(id=id)
        db_api.ip_policy_delete(context, ipp)
