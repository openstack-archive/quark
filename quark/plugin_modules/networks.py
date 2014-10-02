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
from neutron.db import quota_db as qdb
from neutron.extensions import providernet as pnet
from neutron.openstack.common import importutils
from neutron.openstack.common import log as logging
from neutron.openstack.common import uuidutils
from neutron import quota
from oslo.config import cfg

from quark.db import api as db_api
from quark.drivers import registry
from quark import exceptions as q_exc
from quark import ipam
from quark import network_strategy
from quark.plugin_modules import ports
from quark.plugin_modules import subnets
from quark import plugin_views as v
from quark import utils

CONF = cfg.CONF
LOG = logging.getLogger(__name__)
STRATEGY = network_strategy.STRATEGY

ipam_driver = (importutils.import_class(CONF.QUARK.ipam_driver))()


def _adapt_provider_nets(context, network):
    # TODO(mdietz) going to ignore all the boundary and network
    #             type checking for now.
    attrs = network["network"]
    net_type = utils.pop_param(attrs, pnet.NETWORK_TYPE)
    phys_net = utils.pop_param(attrs, pnet.PHYSICAL_NETWORK)
    seg_id = utils.pop_param(attrs, pnet.SEGMENTATION_ID)
    return net_type, phys_net, seg_id


def create_network(context, network):
    """Create a network.

    Create a network which represents an L2 network segment which
    can have a set of subnets and ports associated with it.
    : param context: neutron api request context
    : param network: dictionary describing the network, with keys
        as listed in the RESOURCE_ATTRIBUTE_MAP object in
        neutron/api/v2/attributes.py.  All keys will be populated.
    """
    LOG.info("create_network for tenant %s" % context.tenant_id)

    with context.session.begin():
        net_attrs = network["network"]
        subs = net_attrs.pop("subnets", [])
        # Enforce subnet quotas
        if not context.is_admin:
            if len(subs) > 0:
                v4_count, v6_count = 0, 0
                for s in subs:
                    version = netaddr.IPNetwork(s['subnet']['cidr']).version
                    if version == 6:
                        v6_count += 1
                    else:
                        v4_count += 1
                if v4_count > 0:
                    tenant_q_v4 = context.session.query(qdb.Quota).filter_by(
                        tenant_id=context.tenant_id,
                        resource='v4_subnets_per_network').first()
                    if tenant_q_v4 != -1:
                        quota.QUOTAS.limit_check(
                            context,
                            context.tenant_id,
                            v4_subnets_per_network=v4_count)
                if v6_count > 0:
                    tenant_q_v6 = context.session.query(qdb.Quota).filter_by(
                        tenant_id=context.tenant_id,
                        resource='v6_subnets_per_network').first()
                    if tenant_q_v6 != -1:
                        quota.QUOTAS.limit_check(
                            context,
                            context.tenant_id,
                            v6_subnets_per_network=v6_count)
        # Generate a uuid that we're going to hand to the backend and db
        net_uuid = utils.pop_param(net_attrs, "id", None)
        net_type = None
        if net_uuid and context.is_admin:
            net = db_api.network_find(context, id=net_uuid, scope=db_api.ONE)
            net_type = utils.pop_param(net_attrs, "network_plugin", None)
            if net:
                raise q_exc.NetworkAlreadyExists(id=net_uuid)
        else:
            net_uuid = uuidutils.generate_uuid()

        # TODO(mdietz) this will be the first component registry hook, but
        #             lets make it work first
        pnet_type, phys_net, seg_id = _adapt_provider_nets(context, network)

        ipam_strategy = utils.pop_param(net_attrs, "ipam_strategy", None)
        if not ipam_strategy or not context.is_admin:
            ipam_strategy = CONF.QUARK.default_ipam_strategy

        if not ipam.IPAM_REGISTRY.is_valid_strategy(ipam_strategy):
            raise q_exc.InvalidIpamStrategy(strat=ipam_strategy)
        net_attrs["ipam_strategy"] = ipam_strategy

        # NOTE(mdietz) I think ideally we would create the providernet
        # elsewhere as a separate driver step that could be
        # kept in a plugin and completely removed if desired. We could
        # have a pre-callback/observer on the netdriver create_network
        # that gathers any additional parameters from the network dict

        default_net_type = net_type or CONF.QUARK.default_network_type
        net_driver = registry.DRIVER_REGISTRY.get_driver(default_net_type)
        net_driver.create_network(context, net_attrs["name"],
                                  network_id=net_uuid, phys_type=pnet_type,
                                  phys_net=phys_net, segment_id=seg_id)

        net_attrs["id"] = net_uuid
        net_attrs["tenant_id"] = context.tenant_id
        net_attrs["network_plugin"] = default_net_type
        new_net = db_api.network_create(context, **net_attrs)

        new_subnets = []
        for sub in subs:
            sub["subnet"]["network_id"] = new_net["id"]
            sub["subnet"]["tenant_id"] = context.tenant_id
            s = db_api.subnet_create(context, **sub["subnet"])
            new_subnets.append(s)
        new_net["subnets"] = new_subnets

        # if not security_groups.get_security_groups(
        #        context,
        #        filters={"id": security_groups.DEFAULT_SG_UUID}):
        #    security_groups._create_default_security_group(context)
    return v._make_network_dict(new_net)


def update_network(context, id, network):
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
    with context.session.begin():
        net = db_api.network_find(context, id=id, scope=db_api.ONE)
        if not net:
            raise exceptions.NetworkNotFound(net_id=id)
        # FIXME(amir): RM9305/9709
        if (context.tenant_id != net["tenant_id"] and
                not (context.tenant_id is None and context.is_admin)):
            raise exceptions.NotAuthorized()
        net_dict = network["network"]
        utils.pop_param(net_dict, "network_plugin")
        if not context.is_admin and "ipam_strategy" in net_dict:
            utils.pop_param(net_dict, "ipam_strategy")
        net = db_api.network_update(context, net, **net_dict)

    return v._make_network_dict(net)


def get_network(context, id, fields=None):
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

    network = db_api.network_find(context, id=id, join_subnets=True,
                                  scope=db_api.ONE)
    if not network:
        raise exceptions.NetworkNotFound(net_id=id)
    return v._make_network_dict(network, fields=fields)


def get_networks(context, filters=None, fields=None):
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
    filters = filters or {}
    nets = db_api.network_find(context, join_subnets=True, **filters) or []
    nets = [v._make_network_dict(net, fields=fields) for net in nets]
    return nets


def get_networks_count(context, filters=None):
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


def delete_network(context, id):
    """Delete a network.

    : param context: neutron api request context
    : param id: UUID representing the network to delete.
    """
    LOG.info("delete_network %s for tenant %s" % (id, context.tenant_id))
    with context.session.begin():
        net = db_api.network_find(context, id=id, scope=db_api.ONE)
        if not net:
            raise exceptions.NetworkNotFound(net_id=id)
        # FIXME(amir): RM9305/9709
        if (context.tenant_id != net["tenant_id"] and
                not (context.tenant_id is None and context.is_admin)):
            raise exceptions.NotAuthorized()
        if net.ports:
            raise exceptions.NetworkInUse(net_id=id)
        net_driver = registry.DRIVER_REGISTRY.get_driver(net["network_plugin"])
        net_driver.delete_network(context, id)
        for subnet in net["subnets"]:
            subnets._delete_subnet(context, subnet)
        db_api.network_delete(context, net)


def _diag_network(context, network, fields):
    if not network:
        return False
    net_driver = registry.DRIVER_REGISTRY.get_driver(network["network_plugin"])
    net = v._make_network_dict(network)
    net['ports'] = [p.get('id') for p in network.get('ports', [])]
    if 'subnets' in fields:
        net['subnets'] = [subnets.diagnose_subnet(context, s, fields)
                          for s in network.get('subnets', [])]
    if 'ports' in fields:
        net['ports'] = [ports.diagnose_port(context, s, fields)
                        for s in net['ports']]
    if 'config' in fields or 'status' in fields:
        net.update(net_driver.diag_network(
            context, net['id'], get_status='status' in fields))
    return net


def diagnose_network(context, id, fields):
    if not context.is_admin:
        raise exceptions.NotAuthorized()

    if id == "*":
        return {'networks': [_diag_network(context, net, fields) for
                net in db_api.network_find(context, scope=db_api.ALL)]}
    db_net = db_api.network_find(context, id=id, scope=db_api.ONE)
    if not db_net:
        raise exceptions.NetworkNotFound(net_id=id)
    net = _diag_network(context, db_net, fields)
    return {'networks': net}
