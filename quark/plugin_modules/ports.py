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
from neutron.extensions import securitygroup as sg_ext
from neutron import quota
from neutron_lib import exceptions as n_exc
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import uuidutils

from quark.db import api as db_api
from quark.drivers import registry
from quark.environment import Capabilities
from quark import exceptions as q_exc
from quark import ipam
from quark import network_strategy
from quark import plugin_views as v
from quark import tags
from quark import utils

CONF = cfg.CONF
LOG = logging.getLogger(__name__)
PORT_TAG_REGISTRY = tags.PORT_TAG_REGISTRY
STRATEGY = network_strategy.STRATEGY


# HACK(amir): RM9305: do not allow a tenant to associate a network to a port
# that does not belong to them unless it is publicnet or servicenet
# NOTE(blogan): allow advanced services, such as lbaas, the ability
# to associate a network to a port that does not belong to them
def _raise_if_unauthorized(context, net):
    if (not STRATEGY.is_provider_network(net["id"]) and
            net["tenant_id"] != context.tenant_id and
            not context.is_advsvc):
        raise n_exc.NotAuthorized()


def _get_net_driver(network, port=None):
    port_driver = None
    if port and port.get("network_plugin"):
        port_driver = port.get("network_plugin")

    try:
        return registry.DRIVER_REGISTRY.get_driver(
            network["network_plugin"], port_driver=port_driver)
    except Exception as e:
        raise n_exc.BadRequest(resource="ports",
                               msg="invalid network_plugin: %s" % e)


def _get_ipam_driver(network, port=None):
    network_id = network["id"]
    network_strategy = network["ipam_strategy"]

    # Ask the net driver for a IPAM strategy to use
    # with the given network/default strategy.
    net_driver = _get_net_driver(network, port=port)
    strategy = net_driver.select_ipam_strategy(
        network_id, network_strategy)

    # If the driver has no opinion about which strategy to use,
    # we use the one specified by the network.
    if not strategy:
        strategy = network_strategy

    try:
        return ipam.IPAM_REGISTRY.get_strategy(strategy)
    except Exception as e:
        raise n_exc.BadRequest(resource="ports",
                               msg="invalid ipam_strategy: %s" % e)


# NOTE(morgabra) Backend driver operations return a lot of stuff. We use a
# small subset of this data, so we filter out things we don't care about
# so we can avoid any collisions with real port data.
def _filter_backend_port(backend_port):
    # Collect a list of allowed keys in the driver response
    required_keys = ["uuid", "bridge"]
    tag_keys = [tag for tag in PORT_TAG_REGISTRY.tags.keys()]

    allowed_keys = required_keys + tag_keys
    for k in backend_port.keys():
        if k not in allowed_keys:
            del backend_port[k]


def split_and_validate_requested_subnets(context, net_id, segment_id,
                                         fixed_ips):
    subnets = []
    ip_addresses = {}
    for fixed_ip in fixed_ips:
        subnet_id = fixed_ip.get("subnet_id")
        ip_address = fixed_ip.get("ip_address")
        if not subnet_id:
            raise n_exc.BadRequest(resource="fixed_ips",
                                   msg="subnet_id required")
        if ip_address:
            ip_addresses[ip_address] = subnet_id
        else:
            subnets.append(subnet_id)

    subnets = ip_addresses.values() + subnets

    sub_models = db_api.subnet_find(context, id=subnets, scope=db_api.ALL)
    if len(sub_models) == 0:
        raise n_exc.SubnetNotFound(subnet_id=subnets)

    for s in sub_models:
        if s["network_id"] != net_id:
            raise n_exc.InvalidInput(
                error_message="Requested subnet doesn't belong to requested "
                              "network")

        if segment_id and segment_id != s["segment_id"]:
            raise q_exc.AmbiguousNetworkId(net_id=net_id)

    return ip_addresses, subnets


def create_port(context, port):
    """Create a port

    Create a port which is a connection point of a device (e.g., a VM
    NIC) to attach to a L2 Neutron network.
    : param context: neutron api request context
    : param port: dictionary describing the port, with keys
        as listed in the RESOURCE_ATTRIBUTE_MAP object in
        neutron/api/v2/attributes.py.  All keys will be populated.
    """
    LOG.info("create_port for tenant %s" % context.tenant_id)
    port_attrs = port["port"]

    admin_only = ["mac_address", "device_owner", "bridge", "admin_state_up",
                  "use_forbidden_mac_range", "network_plugin",
                  "instance_node_id"]
    utils.filter_body(context, port_attrs, admin_only=admin_only)

    port_attrs = port["port"]
    mac_address = utils.pop_param(port_attrs, "mac_address", None)
    use_forbidden_mac_range = utils.pop_param(port_attrs,
                                              "use_forbidden_mac_range", False)
    segment_id = utils.pop_param(port_attrs, "segment_id")
    fixed_ips = utils.pop_param(port_attrs, "fixed_ips")

    if "device_id" not in port_attrs:
        port_attrs['device_id'] = ""
    device_id = port_attrs['device_id']

    # NOTE(morgabra) This should be instance.node from nova, only needed
    # for ironic_driver.
    if "instance_node_id" not in port_attrs:
        port_attrs['instance_node_id'] = ""
    instance_node_id = port_attrs['instance_node_id']

    net_id = port_attrs["network_id"]

    port_id = uuidutils.generate_uuid()

    net = db_api.network_find(context, None, None, None, False, id=net_id,
                              scope=db_api.ONE)

    if not net:
        raise n_exc.NetworkNotFound(net_id=net_id)
    _raise_if_unauthorized(context, net)

    # NOTE (Perkins): If a device_id is given, try to prevent multiple ports
    # from being created for a device already attached to the network
    if device_id:
        existing_ports = db_api.port_find(context,
                                          network_id=net_id,
                                          device_id=device_id,
                                          scope=db_api.ONE)
        if existing_ports:
            raise n_exc.BadRequest(
                resource="port", msg="This device is already connected to the "
                "requested network via another port")

    # Try to fail early on quotas and save ourselves some db overhead
    if fixed_ips:
        quota.QUOTAS.limit_check(context, context.tenant_id,
                                 fixed_ips_per_port=len(fixed_ips))

    if not STRATEGY.is_provider_network(net_id):
        # We don't honor segmented networks when they aren't "shared"
        segment_id = None
        port_count = db_api.port_count_all(context, network_id=[net_id],
                                           tenant_id=[context.tenant_id])
        quota.QUOTAS.limit_check(
            context, context.tenant_id,
            ports_per_network=port_count + 1)
    else:
        if not segment_id:
            raise q_exc.AmbiguousNetworkId(net_id=net_id)

    network_plugin = utils.pop_param(port_attrs, "network_plugin")
    if not network_plugin:
        network_plugin = net["network_plugin"]
    port_attrs["network_plugin"] = network_plugin

    ipam_driver = _get_ipam_driver(net, port=port_attrs)
    net_driver = _get_net_driver(net, port=port_attrs)
    # NOTE(morgabra) It's possible that we select a driver different than
    # the one specified by the network. However, we still might need to use
    # this for some operations, so we also fetch it and pass it along to
    # the backend driver we are actually using.
    base_net_driver = _get_net_driver(net)

    # TODO(anyone): security groups are not currently supported on port create.
    #               Please see JIRA:NCP-801
    security_groups = utils.pop_param(port_attrs, "security_groups")
    if security_groups is not None:
        raise q_exc.SecurityGroupsNotImplemented()

    group_ids, security_groups = _make_security_group_list(context,
                                                           security_groups)
    quota.QUOTAS.limit_check(context, context.tenant_id,
                             security_groups_per_port=len(group_ids))
    addresses = []
    backend_port = None

    with utils.CommandManager().execute() as cmd_mgr:
        @cmd_mgr.do
        def _allocate_ips(fixed_ips, net, port_id, segment_id, mac):
            fixed_ip_kwargs = {}
            if fixed_ips:
                if (STRATEGY.is_provider_network(net_id) and
                        not context.is_admin):
                    raise n_exc.NotAuthorized()

                ips, subnets = split_and_validate_requested_subnets(context,
                                                                    net_id,
                                                                    segment_id,
                                                                    fixed_ips)
                fixed_ip_kwargs["ip_addresses"] = ips
                fixed_ip_kwargs["subnets"] = subnets

            ipam_driver.allocate_ip_address(
                context, addresses, net["id"], port_id,
                CONF.QUARK.ipam_reuse_after, segment_id=segment_id,
                mac_address=mac, **fixed_ip_kwargs)

        @cmd_mgr.undo
        def _allocate_ips_undo(addr):
            LOG.info("Rolling back IP addresses...")
            if addresses:
                for address in addresses:
                    try:
                        with context.session.begin():
                            ipam_driver.deallocate_ip_address(context, address)
                    except Exception:
                        LOG.exception("Couldn't release IP %s" % address)

        @cmd_mgr.do
        def _allocate_mac(net, port_id, mac_address,
                          use_forbidden_mac_range=False):
            mac = ipam_driver.allocate_mac_address(
                context, net["id"], port_id, CONF.QUARK.ipam_reuse_after,
                mac_address=mac_address,
                use_forbidden_mac_range=use_forbidden_mac_range)
            return mac

        @cmd_mgr.undo
        def _allocate_mac_undo(mac):
            LOG.info("Rolling back MAC address...")
            if mac:
                try:
                    with context.session.begin():
                        ipam_driver.deallocate_mac_address(context,
                                                           mac["address"])
                except Exception:
                    LOG.exception("Couldn't release MAC %s" % mac)

        @cmd_mgr.do
        def _allocate_backend_port(mac, addresses, net, port_id):
            backend_port = net_driver.create_port(
                context, net["id"],
                port_id=port_id,
                security_groups=group_ids,
                device_id=device_id,
                instance_node_id=instance_node_id,
                mac_address=mac,
                addresses=addresses,
                base_net_driver=base_net_driver)
            _filter_backend_port(backend_port)
            return backend_port

        @cmd_mgr.undo
        def _allocate_back_port_undo(backend_port):
            LOG.info("Rolling back backend port...")
            try:
                backend_port_uuid = None
                if backend_port:
                    backend_port_uuid = backend_port.get("uuid")
                net_driver.delete_port(context, backend_port_uuid)
            except Exception:
                LOG.exception(
                    "Couldn't rollback backend port %s" % backend_port)

        @cmd_mgr.do
        def _allocate_db_port(port_attrs, backend_port, addresses, mac):
            port_attrs["network_id"] = net["id"]
            port_attrs["id"] = port_id
            port_attrs["security_groups"] = security_groups

            LOG.info("Including extra plugin attrs: %s" % backend_port)
            port_attrs.update(backend_port)
            with context.session.begin():
                new_port = db_api.port_create(
                    context, addresses=addresses, mac_address=mac["address"],
                    backend_key=backend_port["uuid"], **port_attrs)

            return new_port

        @cmd_mgr.undo
        def _allocate_db_port_undo(new_port):
            LOG.info("Rolling back database port...")
            if not new_port:
                return
            try:
                with context.session.begin():
                    db_api.port_delete(context, new_port)
            except Exception:
                LOG.exception(
                    "Couldn't rollback db port %s" % backend_port)

        # addresses, mac, backend_port, new_port
        mac = _allocate_mac(net, port_id, mac_address,
                            use_forbidden_mac_range=use_forbidden_mac_range)
        _allocate_ips(fixed_ips, net, port_id, segment_id, mac)
        backend_port = _allocate_backend_port(mac, addresses, net, port_id)
        new_port = _allocate_db_port(port_attrs, backend_port, addresses, mac)

    return v._make_port_dict(new_port)


def update_port(context, id, port):
    """Update values of a port.

    : param context: neutron api request context
    : param id: UUID representing the port to update.
    : param port: dictionary with keys indicating fields to update.
        valid keys are those that have a value of True for 'allow_put'
        as listed in the RESOURCE_ATTRIBUTE_MAP object in
        neutron/api/v2/attributes.py.
    """
    LOG.info("update_port %s for tenant %s" % (id, context.tenant_id))
    port_db = db_api.port_find(context, id=id, scope=db_api.ONE)
    if not port_db:
        raise n_exc.PortNotFound(port_id=id)

    port_dict = port["port"]
    fixed_ips = port_dict.pop("fixed_ips", None)

    admin_only = ["mac_address", "device_owner", "bridge", "admin_state_up",
                  "device_id"]
    always_filter = ["network_id", "backend_key", "network_plugin"]
    utils.filter_body(context, port_dict, admin_only=admin_only,
                      always_filter=always_filter)

    # Pre-check the requested fixed_ips before making too many db trips.
    # Note that this is the only check we need, since this call replaces
    # the entirety of the IP addresses document if fixed_ips are provided.
    if fixed_ips:
        quota.QUOTAS.limit_check(context, context.tenant_id,
                                 fixed_ips_per_port=len(fixed_ips))

    new_security_groups = utils.pop_param(port_dict, "security_groups")
    if new_security_groups is not None:
        if (Capabilities.TENANT_NETWORK_SG not in
                CONF.QUARK.environment_capabilities):
            if not STRATEGY.is_provider_network(port_db["network_id"]):
                raise q_exc.TenantNetworkSecurityGroupRulesNotEnabled()

    if new_security_groups is not None and not port_db["device_id"]:
        raise q_exc.SecurityGroupsRequireDevice()

    group_ids, security_group_mods = _make_security_group_list(
        context, new_security_groups)
    quota.QUOTAS.limit_check(context, context.tenant_id,
                             security_groups_per_port=len(group_ids))

    if fixed_ips is not None:
        # NOTE(mdietz): we want full control over IPAM since
        #              we're allocating by subnet instead of
        #              network.
        ipam_driver = ipam.IPAM_REGISTRY.get_strategy(
            ipam.QuarkIpamANY.get_name())

        addresses, subnet_ids = [], []
        ip_addresses = {}

        for fixed_ip in fixed_ips:
            subnet_id = fixed_ip.get("subnet_id")
            ip_address = fixed_ip.get("ip_address")
            if not (subnet_id or ip_address):
                raise n_exc.BadRequest(
                    resource="fixed_ips",
                    msg="subnet_id or ip_address required")

            if ip_address and not subnet_id:
                raise n_exc.BadRequest(
                    resource="fixed_ips",
                    msg="subnet_id required for ip_address allocation")

            if subnet_id and ip_address:
                ip_netaddr = None
                try:
                    ip_netaddr = netaddr.IPAddress(ip_address).ipv6()
                except netaddr.AddrFormatError:
                    raise n_exc.InvalidInput(
                        error_message="Invalid format provided for ip_address")
                ip_addresses[ip_netaddr] = subnet_id
            else:
                subnet_ids.append(subnet_id)

        port_ips = set([netaddr.IPAddress(int(a["address"]))
                        for a in port_db["ip_addresses"]])
        new_ips = set([a for a in ip_addresses.keys()])

        ips_to_allocate = list(new_ips - port_ips)
        ips_to_deallocate = list(port_ips - new_ips)

        for ip in ips_to_allocate:
            if ip in ip_addresses:
                # NOTE: Fix for RM10187 - we were losing the list of IPs if
                #       more than one IP was to be allocated. Track an
                #       aggregate list instead, and add it to the running total
                #       after each allocate
                allocated = []
                ipam_driver.allocate_ip_address(
                    context, allocated, port_db["network_id"],
                    port_db["id"], reuse_after=None, ip_addresses=[ip],
                    subnets=[ip_addresses[ip]])
                addresses.extend(allocated)

        for ip in ips_to_deallocate:
            ipam_driver.deallocate_ips_by_port(
                context, port_db, ip_address=ip)

        for subnet_id in subnet_ids:
            ipam_driver.allocate_ip_address(
                context, addresses, port_db["network_id"], port_db["id"],
                reuse_after=CONF.QUARK.ipam_reuse_after,
                subnets=[subnet_id])

        # Need to return all existing addresses and the new ones
        if addresses:
            port_dict["addresses"] = port_db["ip_addresses"]
            port_dict["addresses"].extend(addresses)

    # NOTE(morgabra) Updating network_plugin on port objects is explicitly
    # disallowed in the api, so we use whatever exists in the db.
    net_driver = _get_net_driver(port_db.network, port=port_db)
    base_net_driver = _get_net_driver(port_db.network)

    # TODO(anyone): What do we want to have happen here if this fails? Is it
    #               ok to continue to keep the IPs but fail to apply security
    #               groups? Is there a clean way to have a multi-status? Since
    #               we're in a beta-y status, I'm going to let this sit for
    #               a future patch where we have time to solve it well.
    kwargs = {}
    if new_security_groups is not None:
        kwargs["security_groups"] = security_group_mods
    net_driver.update_port(context, port_id=port_db["backend_key"],
                           mac_address=port_db["mac_address"],
                           device_id=port_db["device_id"],
                           base_net_driver=base_net_driver,
                           **kwargs)

    port_dict["security_groups"] = security_group_mods

    with context.session.begin():
        port = db_api.port_update(context, port_db, **port_dict)

    # NOTE(mdietz): fix for issue 112, we wanted the IPs to be in
    #              allocated_at order, so get a fresh object every time
    if port_db in context.session:
        context.session.expunge(port_db)
    port_db = db_api.port_find(context, id=id, scope=db_api.ONE)

    return v._make_port_dict(port_db)


def get_port(context, id, fields=None):
    """Retrieve a port.

    : param context: neutron api request context
    : param id: UUID representing the port to fetch.
    : param fields: a list of strings that are valid keys in a
        port dictionary as listed in the RESOURCE_ATTRIBUTE_MAP
        object in neutron/api/v2/attributes.py. Only these fields
        will be returned.
    """
    LOG.info("get_port %s for tenant %s fields %s" %
             (id, context.tenant_id, fields))
    results = db_api.port_find(context, id=id, fields=fields,
                               scope=db_api.ONE)

    if not results:
        raise n_exc.PortNotFound(port_id=id)

    return v._make_port_dict(results)


def get_ports(context, limit=None, sorts=None, marker=None, page_reverse=False,
              filters=None, fields=None):
    """Retrieve a list of ports.

    The contents of the list depends on the identity of the user
    making the request (as indicated by the context) as well as any
    filters.
    : param context: neutron api request context
    : param filters: a dictionary with keys that are valid keys for
        a port as listed in the RESOURCE_ATTRIBUTE_MAP object
        in neutron/api/v2/attributes.py.  Values in this dictionary
        are an iterable containing values that will be used for an exact
        match comparison for that value.  Each result returned by this
        function will have matched one of the values for each key in
        filters.
    : param fields: a list of strings that are valid keys in a
        port dictionary as listed in the RESOURCE_ATTRIBUTE_MAP
        object in neutron/api/v2/attributes.py. Only these fields
        will be returned.
    """
    LOG.info("get_ports for tenant %s filters %s fields %s" %
             (context.tenant_id, filters, fields))
    if filters is None:
        filters = {}

    if "ip_address" in filters:
        if not context.is_admin:
            raise n_exc.NotAuthorized()
        ips = []
        try:
            ips = [netaddr.IPAddress(ip) for ip in filters.pop("ip_address")]
        except netaddr.AddrFormatError:
            raise n_exc.InvalidInput(
                error_message="Invalid format provided for ip_address")
        query = db_api.port_find_by_ip_address(context, ip_address=ips,
                                               scope=db_api.ALL, **filters)
        ports = []
        for ip in query:
            ports.extend(ip.ports)
    else:
        ports = db_api.port_find(context, limit, sorts, marker,
                                 fields=fields, join_security_groups=True,
                                 **filters)
    return v._make_ports_list(ports, fields)


def get_ports_count(context, filters=None):
    """Return the number of ports.

    The result depends on the identity of the user making the request
    (as indicated by the context) as well as any filters.
    : param context: neutron api request context
    : param filters: a dictionary with keys that are valid keys for
        a port as listed in the RESOURCE_ATTRIBUTE_MAP object
        in neutron/api/v2/attributes.py.  Values in this dictionary
        are an iterable containing values that will be used for an exact
        match comparison for that value.  Each result returned by this
        function will have matched one of the values for each key in
        filters.

    NOTE: this method is optional, as it was not part of the originally
          defined plugin API.
    """
    LOG.info("get_ports_count for tenant %s filters %s" %
             (context.tenant_id, filters))
    return db_api.port_count_all(context, join_security_groups=True, **filters)


def delete_port(context, id):
    """Delete a port.

    : param context: neutron api request context
    : param id: UUID representing the port to delete.
    """
    LOG.info("delete_port %s for tenant %s" % (id, context.tenant_id))

    port = db_api.port_find(context, id=id, scope=db_api.ONE)
    if not port:
        raise n_exc.PortNotFound(port_id=id)

    if 'device_id' in port:  # false is weird, but ignore that
        LOG.info("delete_port %s for tenant %s has device %s" %
                 (id, context.tenant_id, port['device_id']))

    backend_key = port["backend_key"]
    mac_address = netaddr.EUI(port["mac_address"]).value
    ipam_driver = _get_ipam_driver(port["network"], port=port)
    ipam_driver.deallocate_mac_address(context, mac_address)
    ipam_driver.deallocate_ips_by_port(
        context, port, ipam_reuse_after=CONF.QUARK.ipam_reuse_after)

    net_driver = _get_net_driver(port["network"], port=port)
    base_net_driver = _get_net_driver(port["network"])
    net_driver.delete_port(context, backend_key, device_id=port["device_id"],
                           mac_address=port["mac_address"],
                           base_net_driver=base_net_driver)

    with context.session.begin():
        db_api.port_delete(context, port)


def _diag_port(context, port, fields):
    p = v._make_port_dict(port)
    net_driver = _get_net_driver(port.network, port=port)
    if 'config' in fields:
        p.update(net_driver.diag_port(
            context, port["backend_key"], get_status='status' in fields))
    return p


def diagnose_port(context, id, fields):
    if not context.is_admin:
        raise n_exc.NotAuthorized()

    if id == "*":
        return {'ports': [_diag_port(context, port, fields) for
                port in db_api.port_find(context).all()]}
    db_port = db_api.port_find(context, id=id, scope=db_api.ONE)
    if not db_port:
        raise n_exc.PortNotFound(port_id=id)
    port = _diag_port(context, db_port, fields)
    return {'ports': port}


def _make_security_group_list(context, group_ids):
    if not group_ids or not utils.attr_specified(group_ids):
        return ([], [])
    group_ids = list(set(group_ids))
    groups = []
    for gid in group_ids:
        group = db_api.security_group_find(context, id=gid,
                                           scope=db_api.ONE)
        if not group:
            raise sg_ext.SecurityGroupNotFound(id=gid)
        groups.append(group)
    return (group_ids, groups)
