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
from neutron.extensions import securitygroup as sg_ext
from neutron.openstack.common import log as logging
from neutron.openstack.common import uuidutils
from neutron import quota
from oslo.config import cfg

from quark.db import api as db_api
from quark.drivers import registry
from quark import exceptions as q_exc
from quark import ipam
from quark import network_strategy
from quark import plugin_views as v
from quark import utils

CONF = cfg.CONF
LOG = logging.getLogger(__name__)
STRATEGY = network_strategy.STRATEGY


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

    admin_only = ["mac_address", "device_owner", "bridge", "admin_state_up"]
    utils.filter_body(context, port_attrs, admin_only=admin_only)

    port_attrs = port["port"]
    mac_address = utils.pop_param(port_attrs, "mac_address", None)
    segment_id = utils.pop_param(port_attrs, "segment_id")
    fixed_ips = utils.pop_param(port_attrs, "fixed_ips")
    if "device_id" not in port_attrs:
        port_attrs['device_id'] = ""
    device_id = port_attrs['device_id']
    net_id = port_attrs["network_id"]

    port_id = uuidutils.generate_uuid()

    net = db_api.network_find(context, id=net_id, scope=db_api.ONE)
    if not net:
        raise exceptions.NetworkNotFound(net_id=net_id)

    # NOTE (Perkins): If a device_id is given, try to prevent multiple ports
    # from being created for a device already attached to the network
    if device_id:
        existing_ports = db_api.port_find(context,
                                          network_id=net_id,
                                          device_id=device_id,
                                          scope=db_api.ONE)
        if existing_ports:
            raise exceptions.BadRequest(
                resource="port", msg="This device is already connected to the "
                "requested network via another port")

    if not STRATEGY.is_parent_network(net_id):
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

    ipam_driver = ipam.IPAM_REGISTRY.get_strategy(net["ipam_strategy"])

    net_driver = registry.DRIVER_REGISTRY.get_driver(net["network_plugin"])

    # TODO(anyone): security groups are not currently supported on port create,
    #               nor on isolated networks today. Please see RM8615
    security_groups = utils.pop_param(port_attrs, "security_groups")
    if security_groups:
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
            subnets = []
            ip_addresses = {}
            if fixed_ips:
                for fixed_ip in fixed_ips:
                    subnet_id = fixed_ip.get("subnet_id")
                    ip_address = fixed_ip.get("ip_address")
                    if not subnet_id:
                        raise exceptions.BadRequest(
                            resource="fixed_ips",
                            msg="subnet_id required")
                    if ip_address:
                        ip_addresses[ip_address] = subnet_id
                    else:
                        subnets.append(subnet_id)

                ips = ip_addresses.keys()
                subnets = ip_addresses.values() + subnets

                ipam_driver.allocate_ip_address(
                    context, addresses, net["id"], port_id,
                    CONF.QUARK.ipam_reuse_after, segment_id=segment_id,
                    ip_addresses=ips, subnets=subnets,
                    mac_address=mac)
            else:
                ipam_driver.allocate_ip_address(
                    context, addresses, net["id"], port_id,
                    CONF.QUARK.ipam_reuse_after, segment_id=segment_id,
                    mac_address=mac)

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
        def _allocate_mac(net, port_id, mac_address):
            mac = ipam_driver.allocate_mac_address(
                context, net["id"], port_id, CONF.QUARK.ipam_reuse_after,
                mac_address=mac_address)
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
            backend_port = net_driver.create_port(context, net["id"],
                                                  port_id=port_id,
                                                  security_groups=group_ids,
                                                  device_id=device_id)
            return backend_port

        @cmd_mgr.undo
        def _allocate_back_port_undo(backend_port):
            LOG.info("Rolling back backend port...")
            try:
                net_driver.delete_port(context, backend_port["uuid"])
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
        mac = _allocate_mac(net, port_id, mac_address)
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
        raise exceptions.PortNotFound(port_id=id)

    port_dict = port["port"]
    fixed_ips = port_dict.pop("fixed_ips", None)

    admin_only = ["mac_address", "device_owner", "bridge", "admin_state_up",
                  "device_id"]
    always_filter = ["network_id", "backend_key"]
    utils.filter_body(context, port_dict, admin_only=admin_only,
                      always_filter=always_filter)

    # TODO(anyone): security groups are not currently supported on port create,
    #               nor on isolated networks today. Please see RM8615
    security_groups = utils.pop_param(port_dict, "security_groups")
    if security_groups:
        if not STRATEGY.is_parent_network(port_db["network_id"]):
            raise q_exc.TenantNetworkSecurityGroupsNotImplemented()

    group_ids, security_groups = _make_security_group_list(context,
                                                           security_groups)
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
                raise exceptions.BadRequest(
                    resource="fixed_ips",
                    msg="subnet_id or ip_address required")

            if ip_address and not subnet_id:
                raise exceptions.BadRequest(
                    resource="fixed_ips",
                    msg="subnet_id required for ip_address allocation")

            if subnet_id and ip_address:
                ip_netaddr = netaddr.IPAddress(ip_address).ipv6()
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
                ipam_driver.allocate_ip_address(
                    context, addresses, port_db["network_id"],
                    port_db["id"], reuse_after=None, ip_addresses=[ip],
                    subnets=[ip_addresses[ip]])

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

    net_driver = registry.DRIVER_REGISTRY.get_driver(
        port_db.network["network_plugin"])

    # TODO(anyone): What do we want to have happen here if this fails? Is it
    #               ok to continue to keep the IPs but fail to apply security
    #               groups? Is there a clean way to have a multi-status? Since
    #               we're in a beta-y status, I'm going to let this sit for
    #               a future patch where we have time to solve it well.
    net_driver.update_port(context, port_id=port_db["backend_key"],
                           mac_address=port_db["mac_address"],
                           device_id=port_db["device_id"],
                           security_groups=security_groups)

    port_dict["security_groups"] = security_groups

    with context.session.begin():
        port = db_api.port_update(context, port_db, **port_dict)

    # NOTE(mdietz): fix for issue 112, we wanted the IPs to be in
    #              allocated_at order, so get a fresh object every time
    if port_db in context.session:
        context.session.expunge(port_db)
    port_db = db_api.port_find(context, id=id, scope=db_api.ONE)

    return v._make_port_dict(port_db)


def post_update_port(context, id, port):
    LOG.info("post_update_port %s for tenant %s" % (id, context.tenant_id))
    if not port.get("port"):
        raise exceptions.BadRequest(resource="ports",
                                    msg="Port body required")

    port_db = db_api.port_find(context, id=id, scope=db_api.ONE)
    if not port_db:
        raise exceptions.PortNotFound(port_id=id, net_id="")

    port = port["port"]
    if "fixed_ips" in port and port["fixed_ips"]:
        for ip in port["fixed_ips"]:
            address = None
            ipam_driver = ipam.IPAM_REGISTRY.get_strategy(
                port_db["network"]["ipam_strategy"])
            if ip:
                if "ip_id" in ip:
                    ip_id = ip["ip_id"]
                    address = db_api.ip_address_find(
                        context, id=ip_id, tenant_id=context.tenant_id,
                        scope=db_api.ONE)
                elif "ip_address" in ip:
                    ip_address = ip["ip_address"]
                    net_address = netaddr.IPAddress(ip_address)
                    address = db_api.ip_address_find(
                        context, ip_address=net_address,
                        network_id=port_db["network_id"],
                        tenant_id=context.tenant_id, scope=db_api.ONE)
                    if not address:
                        address = ipam_driver.allocate_ip_address(
                            context, port_db["network_id"], id,
                            CONF.QUARK.ipam_reuse_after,
                            ip_addresses=[ip_address])
            else:
                address = ipam_driver.allocate_ip_address(
                    context, port_db["network_id"], id,
                    CONF.QUARK.ipam_reuse_after)

        address["deallocated"] = 0

        already_contained = False
        for port_address in port_db["ip_addresses"]:
            if address["id"] == port_address["id"]:
                already_contained = True
                break

        if not already_contained:
            port_db["ip_addresses"].append(address)
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
        raise exceptions.PortNotFound(port_id=id, net_id='')

    return v._make_port_dict(results)


def get_ports(context, filters=None, fields=None):
    """Retrieve a list of ports.

    The contents of the list depends on the identity of the user
    making the request (as indicated by the context) as well as any
    filters.
    : param context: neutron api request context
    : param filters: a dictionary with keys that are valid keys for
        a port as listed in the RESOURCE_ATTRIBUTE_MAP object
        in neutron/api/v2/attributes.py.  Values in this dictiontary
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
            raise exceptions.NotAuthorized()
        ips = [netaddr.IPAddress(ip) for ip in filters.pop("ip_address")]
        query = db_api.port_find_by_ip_address(context, ip_address=ips,
                                               scope=db_api.ALL, **filters)
        ports = []
        for ip in query:
            ports.extend(ip.ports)
    else:
        ports = db_api.port_find(context, fields=fields,
                                 join_security_groups=True, **filters)
    return v._make_ports_list(ports, fields)


def get_ports_count(context, filters=None):
    """Return the number of ports.

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
    LOG.info("get_ports_count for tenant %s filters %s" %
             (context.tenant_id, filters))
    return db_api.port_count_all(context, join_security_groups=True, **filters)


def delete_port(context, id):
    """Delete a port.

    : param context: neutron api request context
    : param id: UUID representing the port to delete.
    """
    LOG.info("delete_port %s for tenant %s" %
             (id, context.tenant_id))

    port = db_api.port_find(context, id=id, scope=db_api.ONE)
    if not port:
        raise exceptions.PortNotFound(net_id=id)

    backend_key = port["backend_key"]
    mac_address = netaddr.EUI(port["mac_address"]).value
    ipam_driver = ipam.IPAM_REGISTRY.get_strategy(
        port["network"]["ipam_strategy"])
    ipam_driver.deallocate_mac_address(context, mac_address)
    ipam_driver.deallocate_ips_by_port(
        context, port, ipam_reuse_after=CONF.QUARK.ipam_reuse_after)

    net_driver = registry.DRIVER_REGISTRY.get_driver(
        port.network["network_plugin"])
    net_driver.delete_port(context, backend_key)

    with context.session.begin():
        db_api.port_delete(context, port)


def _diag_port(context, port, fields):
    p = v._make_port_dict(port)
    net_driver = registry.DRIVER_REGISTRY.get_driver(
        port.network["network_plugin"])
    if 'config' in fields:
        p.update(net_driver.diag_port(
            context, port["backend_key"], get_status='status' in fields))
    return p


def diagnose_port(context, id, fields):
    if not context.is_admin:
        raise exceptions.NotAuthorized()

    if id == "*":
        return {'ports': [_diag_port(context, port, fields) for
                port in db_api.port_find(context).all()]}
    db_port = db_api.port_find(context, id=id, scope=db_api.ONE)
    if not db_port:
        raise exceptions.PortNotFound(port_id=id, net_id='')
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
