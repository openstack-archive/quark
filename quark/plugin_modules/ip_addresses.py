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
from oslo.config import cfg
from oslo_log import log as logging
import webob

from quark.db import api as db_api
from quark.db import ip_types
from quark import exceptions as quark_exceptions
from quark import ipam
from quark import plugin_views as v

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

# NOTE(thomasem): Since IP addresses are only at the subnet level, use
# the QuarkIpamANY strategy, due to other IPAM strategies only being
# relevant at the network level (port create).
ipam_driver = ipam.IPAM_REGISTRY.get_strategy(ipam.QuarkIpamANY.get_name())


def get_ip_addresses(context, **filters):
    LOG.info("get_ip_addresses for tenant %s" % context.tenant_id)
    filters["_deallocated"] = False
    addrs = db_api.ip_address_find(context, scope=db_api.ALL, **filters)
    return [v._make_ip_dict(ip) for ip in addrs]


def get_ip_address(context, id):
    LOG.info("get_ip_address %s for tenant %s" %
             (id, context.tenant_id))
    addr = db_api.ip_address_find(context, id=id, scope=db_api.ONE)
    if not addr:
        raise quark_exceptions.IpAddressNotFound(addr_id=id)
    return v._make_ip_dict(addr)


def validate_ports_on_network_and_same_segment(ports, network_id):
    first_segment = None
    for port in ports:
        addresses = port.get("ip_addresses", [])
        for address in addresses:
            if address["network_id"] != network_id:
                raise exceptions.BadRequest(resource="ip_addresses",
                                            msg="Must have ports connected to"
                                                " the requested network")
            segment_id = address.subnet.get("segment_id")
            first_segment = first_segment or segment_id
            if segment_id != first_segment:
                raise exceptions.BadRequest(resource="ip_addresses",
                                            msg="Segment id's do not match.")


def _shared_ip_request(ip_address):
    port_ids = ip_address.get('ip_address', {}).get('port_ids', [])
    return len(port_ids) > 1


def _can_be_shared(address_model):
    # Don't share IP if any of the assocs is enabled
    return not any(a.enabled for a in address_model.associations)


def create_ip_address(context, body):
    LOG.info("create_ip_address for tenant %s" % context.tenant_id)
    address_type = (ip_types.SHARED if _shared_ip_request(body)
                    else ip_types.FIXED)
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
        raise exceptions.BadRequest(resource="ip_addresses",
                                    msg="version is required.")
    if not network_id:
        raise exceptions.BadRequest(resource="ip_addresses",
                                    msg="network_id is required.")

    new_addresses = []
    ports = []
    with context.session.begin():
        if network_id and device_ids:
            for device_id in device_ids:
                port = db_api.port_find(
                    context, network_id=network_id, device_id=device_id,
                    tenant_id=context.tenant_id, scope=db_api.ONE)
                ports.append(port)
        elif port_ids:
            for port_id in port_ids:

                port = db_api.port_find(context, id=port_id,
                                        tenant_id=context.tenant_id,
                                        scope=db_api.ONE)
                ports.append(port)

        if not ports:
            raise exceptions.PortNotFound(port_id=port_ids,
                                          net_id=network_id)

    validate_ports_on_network_and_same_segment(ports, network_id)

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
                                    address_type=address_type)
    with context.session.begin():
        new_address = db_api.port_associate_ip(context, ports,
                                               new_addresses[0])
    return v._make_ip_dict(new_address)


def _get_deallocated_override():
    """This function exists to mock and for future requirements if needed."""
    return '2000-01-01 00:00:00'


def _raise_if_shared_and_enabled(address_request, address_model):
    if (_shared_ip_request(address_request)
            and not _can_be_shared(address_model)):
        raise exceptions.BadRequest(
            resource="ip_addresses",
            msg="This IP address is in use on another port and cannot be "
                "shared")


def update_ip_address(context, id, ip_address):
    LOG.info("update_ip_address %s for tenant %s" %
             (id, context.tenant_id))
    ports = []
    with context.session.begin():
        address = db_api.ip_address_find(
            context, id=id, tenant_id=context.tenant_id, scope=db_api.ONE)
        if not address:
            raise exceptions.NotFound(
                message="No IP address found with id=%s" % id)

        reset = ip_address['ip_address'].get('reset_allocation_time', False)
        if reset and address['deallocated'] == 1:
            if context.is_admin:
                LOG.info("IP's deallocated time being manually reset")
                address['deallocated_at'] = _get_deallocated_override()
            else:
                msg = "Modification of reset_allocation_time requires admin"
                raise webob.exc.HTTPForbidden(detail=msg)

        port_ids = ip_address['ip_address'].get('port_ids')

        if port_ids:
            _raise_if_shared_and_enabled(ip_address, address)
            ports = db_api.port_find(context, tenant_id=context.tenant_id,
                                     id=port_ids, scope=db_api.ALL)
            # NOTE(name): could be considered inefficient because we're
            # converting to a list to check length. Maybe revisit
            if len(ports) != len(port_ids):
                raise exceptions.NotFound(
                    message="No ports not found with ids=%s" % port_ids)

            validate_ports_on_network_and_same_segment(ports,
                                                       address["network_id"])

            LOG.info("Updating IP address, %s, to only be used by the"
                     "following ports:  %s" % (address.address_readable,
                                               [p.id for p in ports]))
            new_address = db_api.update_port_associations_for_ip(context,
                                                                 ports,
                                                                 address)
        else:
            if port_ids is not None:
                ipam_driver.deallocate_ip_address(
                    context, address)
            return v._make_ip_dict(address)
    return v._make_ip_dict(new_address)
