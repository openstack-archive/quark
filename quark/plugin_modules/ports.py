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
from neutron.openstack.common import importutils
from neutron.openstack.common import log as logging
from neutron.openstack.common import uuidutils
from neutron import quota
from oslo.config import cfg

from quark.db import api as db_api
from quark import plugin_views as v
from quark import utils

CONF = cfg.CONF
LOG = logging.getLogger("neutron.quark")

ipam_driver = (importutils.import_class(CONF.QUARK.ipam_driver))()
net_driver = (importutils.import_class(CONF.QUARK.net_driver))()
net_driver.load_config(CONF.QUARK.net_driver_cfg)


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
    mac_address = utils.pop_param(port_attrs, "mac_address", None)
    segment_id = utils.pop_param(port_attrs, "segment_id")
    fixed_ips = utils.pop_param(port_attrs, "fixed_ips")
    net_id = port_attrs["network_id"]
    addresses = []

    port_id = uuidutils.generate_uuid()

    net = db_api.network_find(context, id=net_id, shared=True,
                              segment_id=segment_id, scope=db_api.ONE)
    if not net:
        # Maybe it's a tenant network
        net = db_api.network_find(context, id=net_id, scope=db_api.ONE)
        if not net:
            raise exceptions.NetworkNotFound(net_id=net_id)

    quota.QUOTAS.limit_check(
        context, context.tenant_id,
        ports_per_network=len(net.get('ports', [])) + 1)

    if fixed_ips:
        for fixed_ip in fixed_ips:
            subnet_id = fixed_ip.get("subnet_id")
            ip_address = fixed_ip.get("ip_address")
            if not (subnet_id and ip_address):
                raise exceptions.BadRequest(
                    resource="fixed_ips",
                    msg="subnet_id and ip_address required")
            addresses.append(ipam_driver.allocate_ip_address(
                context, net["id"], port_id, CONF.QUARK.ipam_reuse_after,
                ip_address=ip_address))
    else:
        addresses.append(ipam_driver.allocate_ip_address(
            context, net["id"], port_id, CONF.QUARK.ipam_reuse_after))

    group_ids, security_groups = v.make_security_group_list(
        context, port["port"].pop("security_groups", None))
    mac = ipam_driver.allocate_mac_address(context, net["id"], port_id,
                                           CONF.QUARK.ipam_reuse_after,
                                           mac_address=mac_address)
    mac_address_string = str(netaddr.EUI(mac['address'],
                                         dialect=netaddr.mac_unix))
    address_pairs = [{'mac_address': mac_address_string,
                      'ip_address': address.get('address_readable', '')}
                     for address in addresses]
    backend_port = net_driver.create_port(context, net["id"], port_id=port_id,
                                          security_groups=group_ids,
                                          allowed_pairs=address_pairs)

    port_attrs["network_id"] = net["id"]
    port_attrs["id"] = port_id
    port_attrs["security_groups"] = security_groups
    new_port = db_api.port_create(
        context, addresses=addresses, mac_address=mac["address"],
        backend_key=backend_port["uuid"], **port_attrs)
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

    address_pairs = []
    fixed_ips = port["port"].pop("fixed_ips", None)
    if fixed_ips:
        ipam_driver.deallocate_ip_address(
            context, port_db, ipam_reuse_after=CONF.QUARK.ipam_reuse_after)
        addresses = []
        for fixed_ip in fixed_ips:
            subnet_id = fixed_ip.get("subnet_id")
            ip_address = fixed_ip.get("ip_address")
            if not (subnet_id and ip_address):
                raise exceptions.BadRequest(
                    resource="fixed_ips",
                    msg="subnet_id and ip_address required")
            # Note: we don't allow overlapping subnets, thus subnet_id is
            #       ignored.
            addresses.append(ipam_driver.allocate_ip_address(
                context, port_db["network_id"], id,
                CONF.QUARK.ipam_reuse_after, ip_address=ip_address))
        port["port"]["addresses"] = addresses
        mac_address_string = str(netaddr.EUI(port_db.mac_address,
                                             dialect=netaddr.mac_unix))
        address_pairs = [{'mac_address': mac_address_string,
                          'ip_address':
                          address.get('address_readable', '')}
                         for address in addresses]

    group_ids, security_groups = v.make_security_group_list(
        context, port["port"].pop("security_groups", None))
    net_driver.update_port(context, port_id=port_db.backend_key,
                           security_groups=group_ids,
                           allowed_pairs=address_pairs)

    port["port"]["security_groups"] = security_groups
    port = db_api.port_update(context, port_db, **port["port"])
    return v._make_port_dict(port)


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
            if ip:
                if "ip_id" in ip:
                    ip_id = ip["ip_id"]
                    address = db_api.ip_address_find(
                        context,
                        id=ip_id,
                        tenant_id=context.tenant_id,
                        scope=db_api.ONE)
                elif "ip_address" in ip:
                    ip_address = ip["ip_address"]
                    net_address = netaddr.IPAddress(ip_address)
                    address = db_api.ip_address_find(
                        context,
                        ip_address=net_address,
                        network_id=port_db["network_id"],
                        tenant_id=context.tenant_id,
                        scope=db_api.ONE)
                    if not address:
                        address = ipam_driver.allocate_ip_address(
                            context, port_db["network_id"], id,
                            CONF.QUARK.ipam_reuse_after, ip_address=ip_address)
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
    query = db_api.port_find(context, fields=fields, **filters)
    return v._make_ports_list(query, fields)


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
    return db_api.port_count_all(context, **filters)


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
    ipam_driver.deallocate_mac_address(context, mac_address)
    ipam_driver.deallocate_ip_address(
        context, port, ipam_reuse_after=CONF.QUARK.ipam_reuse_after)
    db_api.port_delete(context, port)
    net_driver.delete_port(context, backend_key)


def disassociate_port(context, id, ip_address_id):
    """Disassociates a port from an IP address.

    : param context: neutron api request context
    : param id: UUID representing the port to disassociate.
    : param ip_address_id: UUID representing the IP address to
    disassociate.
    """
    LOG.info("disassociate_port %s for tenant %s ip_address_id %s" %
            (id, context.tenant_id, ip_address_id))
    port = db_api.port_find(context, id=id, ip_address_id=[ip_address_id],
                            scope=db_api.ONE)

    if not port:
        raise exceptions.PortNotFound(port_id=id, net_id='')

    the_address = [address for address in port["ip_addresses"]
                   if address["id"] == ip_address_id][0]
    port["ip_addresses"] = [address for address in port["ip_addresses"]
                            if address.id != ip_address_id]

    if len(the_address["ports"]) == 0:
        the_address["deallocated"] = 1
    return v._make_port_dict(port)
