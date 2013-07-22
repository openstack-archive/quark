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

from neutron.common import exceptions
from neutron.openstack.common import log as logging
from oslo.config import cfg

from quark.db import api as db_api
from quark import exceptions as quark_exceptions
from quark import plugin_views as v


CONF = cfg.CONF
LOG = logging.getLogger("neutron.quark")
DEFAULT_SG_UUID = "00000000-0000-0000-0000-000000000000"


def create_ip_policy(context, ip_policy):
    LOG.info("create_ip_policy for tenant %s" % context.tenant_id)

    ipp = ip_policy["ip_policy"]

    if not ipp.get("exclude"):
        raise exceptions.BadRequest(resource="ip_policy",
                                    msg="Empty ip_policy.exclude regions")

    ipp["exclude"] = netaddr.IPSet(ipp["exclude"])
    network_id = ipp.get("network_id")
    subnet_id = ipp.get("subnet_id")

    model = None
    if subnet_id:
        model = db_api.subnet_find(context, id=subnet_id, scope=db_api.ONE)
        if not model:
            raise exceptions.SubnetNotFound(id=subnet_id)
    elif network_id:
        model = db_api.network_find(context, id=network_id,
                                    scope=db_api.ONE)
        if not model:
            raise exceptions.NetworkNotFound(id=network_id)
    else:
        raise exceptions.BadRequest(
            resource="ip_policy",
            msg="network_id or subnet_id unspecified")

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


def delete_ip_policy(context, id):
    LOG.info("delete_ip_policy %s for tenant %s" % (id, context.tenant_id))
    ipp = db_api.ip_policy_find(context, id=id, scope=db_api.ONE)
    if not ipp:
        raise quark_exceptions.IPPolicyNotFound(id=id)
    db_api.ip_policy_delete(context, ipp)
