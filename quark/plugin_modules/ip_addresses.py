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

from neutron_lib import exceptions as n_exc
from oslo_config import cfg
from oslo_log import log as logging
import webob

from quark.db import api as db_api
from quark.db import ip_types
from quark import exceptions as q_exc
from quark import ipam
from quark import plugin_views as v

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

# NOTE(roaet): this number includes the assumed 'given ips' and any additional
total_ips_on_port = {'00000000-0000-0000-0000-000000000000': 6,
                     '11111111-1111-1111-1111-111111111111': 1,
                     '*': 5}

# NOTE(roaet): shared ips are treated like any other IP and will consume
# from total_ips_on_port
shared_ip_on_network = {'00000000-0000-0000-0000-000000000000': 5,
                        '11111111-1111-1111-1111-111111111111': 0,
                        '*': -1}

quark_ip_addr_opts = [
    cfg.BoolOpt('ipaddr_allow_fixed_ip',
                default=False,
                help=_('Controls if /ip_addresses can make fixed IPs or not')),
    cfg.DictOpt('total_ips_allowed_on_port',
                default=total_ips_on_port,
                help=_('Defines how many IPs may be on a port by network in '
                       'key:quantity format')),
    cfg.DictOpt('shared_ips_allowed_on_network',
                default=shared_ip_on_network,
                help=_('Defines how many shared IPs may be made on a network '
                       'in key:quantity format'))
]

CONF.register_opts(quark_ip_addr_opts, "QUARK")

# NOTE(thomasem): Since IP addresses are only at the subnet level, use
# the QuarkIpamANY strategy, due to other IPAM strategies only being
# relevant at the network level (port create).
ipam_driver = ipam.IPAM_REGISTRY.get_strategy(ipam.QuarkIpamANY.get_name())


def _can_add_ip_to_port_on_network(context, network_id, db_port):
    return True


def _can_create_shared_ip_on_network(context, network_id):
    return True


def get_ip_addresses(context, **filters):
    LOG.info("get_ip_addresses for tenant %s" % context.tenant_id)
    if not filters:
        filters = {}
    if 'type' in filters:
        filters['address_type'] = filters['type']
    filters["_deallocated"] = False
    addrs = db_api.ip_address_find(context, scope=db_api.ALL, **filters)
    return [v._make_ip_dict(ip) for ip in addrs]


def get_ip_address(context, id):
    LOG.info("get_ip_address %s for tenant %s" %
             (id, context.tenant_id))
    filters = {}
    filters["_deallocated"] = False
    addr = db_api.ip_address_find(context, id=id, scope=db_api.ONE, **filters)
    if not addr:
        raise q_exc.IpAddressNotFound(addr_id=id)
    return v._make_ip_dict(addr)


def validate_and_fetch_segment(ports, network_id):
    first_segment = None
    segment_id = None
    for port in ports:
        addresses = port.get("ip_addresses", [])
        for address in addresses:
            if address["network_id"] != network_id:
                raise n_exc.BadRequest(resource="ip_addresses",
                                       msg="Must have ports connected to"
                                           " the requested network")
            segment_id = address.subnet.get("segment_id")
            first_segment = first_segment or segment_id
            if segment_id != first_segment:
                raise n_exc.BadRequest(resource="ip_addresses",
                                       msg="Segment id's do not match.")
    return segment_id


def validate_port_ip_quotas(context, network, ports):
    if network not in CONF.QUARK.total_ips_allowed_on_port:
        network = '*'
    limit = CONF.QUARK.total_ips_allowed_on_port.get(network)
    if limit < 0:
        return
    for port in ports:
        if len(port.associations) + 1 > limit:
            raise q_exc.CannotAddMoreIPsToPort()


def validate_shared_ips_quotas(context, network, addresses):
    if network not in CONF.QUARK.shared_ips_allowed_on_network:
        network = '*'
    limit = CONF.QUARK.shared_ips_allowed_on_network.get(network)
    if limit < 0:
        return
    if len(addresses) + 1 > limit:
        raise q_exc.CannotCreateMoreSharedIPs()


def _shared_ip_request(ip_address):
    port_ids = ip_address.get('ip_address', {}).get('port_ids', [])
    device_ids = ip_address.get('ip_address', {}).get('device_ids', [])
    return len(port_ids) > 1 or len(device_ids) > 1


def _shared_ip_and_active(ip_address, except_port=None):
    if ip_address.is_shared() and ip_address.has_shared_owner():
        return True
    return False


def _can_be_shared(address_model):
    # Don't share IP if any of the assocs is enabled
    return not any(a.enabled for a in address_model.associations)


def create_ip_address(context, body):
    LOG.info("create_ip_address for tenant %s" % context.tenant_id)
    iptype = (ip_types.SHARED if _shared_ip_request(body)
              else ip_types.FIXED)
    if 'ip_address' not in body:
        raise n_exc.BadRequest(resource="ip_addresses",
                               msg="Invalid request body.")
    if iptype == ip_types.FIXED and not CONF.QUARK.ipaddr_allow_fixed_ip:
        raise n_exc.BadRequest(resource="ip_addresses",
                               msg="Only shared IPs may be made with "
                                   "this resource.")
    ip_dict = body.get("ip_address")
    port_ids = ip_dict.get('port_ids', [])
    network_id = ip_dict.get('network_id')
    device_ids = ip_dict.get('device_ids')
    ip_version = ip_dict.get('version')
    ip_address = ip_dict.get('ip_address')
    # If no version is passed, you would get what the network provides,
    # which could be both v4 and v6 addresses. Rather than allow for such
    # an ambiguous outcome, we'll raise instead
    if not ip_version:
        raise n_exc.BadRequest(resource="ip_addresses",
                               msg="version is required.")
    if network_id is None:
        raise n_exc.BadRequest(resource="ip_addresses",
                               msg="network_id is required.")
    if network_id == "":
        raise n_exc.NetworkNotFound(net_id=network_id)
    net = db_api.network_find(context, None, None, None, False,
                              id=network_id, scope=db_api.ONE)
    if not net:
        raise n_exc.NetworkNotFound(net_id=network_id)
    if not port_ids and not device_ids:
        raise n_exc.BadRequest(resource="ip_addresses",
                               msg="port_ids or device_ids required.")

    new_addresses = []
    ports = []
    by_device = False
    with context.session.begin():
        if network_id and device_ids:
            by_device = True
            for device_id in device_ids:
                port = db_api.port_find(
                    context, network_id=network_id, device_id=device_id,
                    tenant_id=context.tenant_id, scope=db_api.ONE)
                if port is not None:
                    ports.append(port)
        elif port_ids:
            for port_id in port_ids:

                port = db_api.port_find(context, id=port_id,
                                        tenant_id=context.tenant_id,
                                        scope=db_api.ONE)
                if port is not None:
                    ports.append(port)

        if not ports:
            raise n_exc.PortNotFoundOnNetwork(port_id=port_ids,
                                              net_id=network_id)

    if ((by_device and len(device_ids) != len(ports)) or
            (not by_device and len(port_ids) != len(ports))):
        raise q_exc.NotAllPortOrDeviceFound()

    segment_id = validate_and_fetch_segment(ports, network_id)
    if iptype == ip_types.SHARED:
        old_addresses = db_api.ip_address_find(context,
                                               network_id=network_id,
                                               address_type=ip_types.SHARED,
                                               scope=db_api.ALL)
        validate_shared_ips_quotas(context, network_id, old_addresses)
    validate_port_ip_quotas(context, network_id, ports)

    # Shared Ips are only new IPs. Two use cases: if we got device_id
    # or if we got port_ids. We should check the case where we got port_ids
    # and device_ids. The device_id must have a port on the network,
    # and any port_ids must also be on that network already. If we have
    # more than one port by this step, it's considered a shared IP,
    # and therefore will be marked as unconfigured (enabled=False)
    # for all ports.
    ipam_driver.allocate_ip_address(context, new_addresses, network_id,
                                    None, CONF.QUARK.ipam_reuse_after,
                                    version=ip_version,
                                    ip_addresses=[ip_address]
                                    if ip_address else [],
                                    segment_id=segment_id,
                                    address_type=iptype)
    with context.session.begin():
        address = new_addresses[0]
        new_address = db_api.port_associate_ip(context, ports, address)
    return v._make_ip_dict(new_address)


def _get_deallocated_override():
    """This function exists to mock and for future requirements if needed."""
    return '2000-01-01 00:00:00'


def _raise_if_shared_and_enabled(address_request, address_model):
    if (_shared_ip_request(address_request)
            and not _can_be_shared(address_model)):
        raise n_exc.BadRequest(
            resource="ip_addresses",
            msg="This IP address is in use on another port and cannot be "
                "shared")


def update_ip_address(context, id, ip_address):
    """Due to NCP-1592 ensure that address_type cannot change after update."""
    LOG.info("update_ip_address %s for tenant %s" % (id, context.tenant_id))
    ports = []
    if 'ip_address' not in ip_address:
        raise n_exc.BadRequest(resource="ip_addresses",
                               msg="Invalid request body.")
    with context.session.begin():
        address = db_api.ip_address_find(context, id=id, scope=db_api.ONE)
        if not address:
            raise q_exc.IpAddressNotFound(addr_id=id)
        iptype = address.address_type
        if iptype == ip_types.FIXED and not CONF.QUARK.ipaddr_allow_fixed_ip:
            raise n_exc.BadRequest(
                resource="ip_addresses",
                msg="Fixed ips cannot be updated using this interface.")

        reset = ip_address['ip_address'].get('reset_allocation_time', False)
        if reset and address['deallocated'] == 1:
            if context.is_admin:
                LOG.info("IP's deallocated time being manually reset")
                address['deallocated_at'] = _get_deallocated_override()
            else:
                msg = "Modification of reset_allocation_time requires admin"
                raise webob.exc.HTTPForbidden(detail=msg)

        port_ids = ip_address['ip_address'].get('port_ids', None)

        if port_ids is not None and not port_ids:
            raise n_exc.BadRequest(
                resource="ip_addresses",
                msg="Cannot be updated with empty port_id list")

        if iptype == ip_types.SHARED:
            has_owner = address.has_any_shared_owner()

        if port_ids:
            if iptype == ip_types.FIXED and len(port_ids) > 1:
                raise n_exc.BadRequest(
                    resource="ip_addresses",
                    msg="Fixed ips cannot be updated with more than one port.")

            _raise_if_shared_and_enabled(ip_address, address)
            ports = db_api.port_find(context, tenant_id=context.tenant_id,
                                     id=port_ids, scope=db_api.ALL)
            # NOTE(name): could be considered inefficient because we're
            # converting to a list to check length. Maybe revisit
            if len(ports) != len(port_ids):
                raise n_exc.PortNotFound(port_id=port_ids)

            validate_and_fetch_segment(ports, address["network_id"])
            validate_port_ip_quotas(context, address.network_id, ports)

            if iptype == ip_types.SHARED and has_owner:
                for assoc in address.associations:
                    pid = assoc.port_id
                    if pid not in port_ids and 'none' != assoc.service:
                        raise q_exc.PortRequiresDisassociation()

            LOG.info("Updating IP address, %s, to only be used by the"
                     "following ports:  %s" % (address.address_readable,
                                               [p.id for p in ports]))
            new_address = db_api.update_port_associations_for_ip(context,
                                                                 ports,
                                                                 address)
        elif iptype == ip_types.SHARED and has_owner:
            raise q_exc.PortRequiresDisassociation()
        else:
            ipam_driver.deallocate_ip_address(context, address)
            return v._make_ip_dict(address)
    return v._make_ip_dict(new_address)


def delete_ip_address(context, id):
    """Delete an ip address.

    : param context: neutron api request context
    : param id: UUID representing the ip address to delete.
    """
    LOG.info("delete_ip_address %s for tenant %s" % (id, context.tenant_id))
    with context.session.begin():
        ip_address = db_api.ip_address_find(
            context, id=id, scope=db_api.ONE)
        if not ip_address or ip_address.deallocated:
            raise q_exc.IpAddressNotFound(addr_id=id)

        iptype = ip_address.address_type
        if iptype == ip_types.FIXED and not CONF.QUARK.ipaddr_allow_fixed_ip:
            raise n_exc.BadRequest(
                resource="ip_addresses",
                msg="Fixed ips cannot be updated using this interface.")

        if ip_address.has_any_shared_owner():
            raise q_exc.PortRequiresDisassociation()

        db_api.update_port_associations_for_ip(context, [], ip_address)

        ipam_driver.deallocate_ip_address(context, ip_address)


def get_ports_for_ip_address(context, ip_id, limit=None, sorts=None,
                             marker=None, page_reverse=False, filters=None,
                             fields=None):
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
    addr = db_api.ip_address_find(context, id=ip_id, scope=db_api.ONE)
    if not addr:
        raise q_exc.IpAddressNotFound(addr_id=ip_id)

    if filters is None:
        filters = {}

    filters['ip_address_id'] = [ip_id]

    ports = db_api.port_find(context, limit, sorts, marker,
                             fields=fields, join_security_groups=True,
                             **filters)
    return v._make_ip_ports_list(addr, ports, fields)


def get_port_for_ip_address(context, ip_id, id, fields=None):
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
    addr = db_api.ip_address_find(context, id=ip_id, scope=db_api.ONE)
    if not addr:
        raise q_exc.IpAddressNotFound(addr_id=ip_id)

    filters = {'ip_address_id': [ip_id]}
    results = db_api.port_find(context, id=id, fields=fields,
                               scope=db_api.ONE, **filters)

    if not results:
        raise n_exc.PortNotFound(port_id=id)

    return v._make_port_for_ip_dict(addr, results)


def update_port_for_ip_address(context, ip_id, id, port):
    """Update values of a port.

    : param context: neutron api request context
    : param ip_id: UUID representing the ip associated with port to update
    : param id: UUID representing the port to update.
    : param port: dictionary with keys indicating fields to update.
        valid keys are those that have a value of True for 'allow_put'
        as listed in the RESOURCE_ATTRIBUTE_MAP object in
        neutron/api/v2/attributes.py.
    """
    LOG.info("update_port %s for tenant %s" % (id, context.tenant_id))
    sanitize_list = ['service']
    with context.session.begin():
        addr = db_api.ip_address_find(context, id=ip_id, scope=db_api.ONE)
        if not addr:
            raise q_exc.IpAddressNotFound(addr_id=ip_id)
        port_db = db_api.port_find(context, id=id, scope=db_api.ONE)
        if not port_db:
            raise q_exc.PortNotFound(port_id=id)
        port_dict = {k: port['port'][k] for k in sanitize_list}

        require_da = False
        service = port_dict.get('service')

        if require_da and _shared_ip_and_active(addr, except_port=id):
            raise q_exc.PortRequiresDisassociation()
        addr.set_service_for_port(port_db, service)
        context.session.add(addr)
    return v._make_port_for_ip_dict(addr, port_db)
