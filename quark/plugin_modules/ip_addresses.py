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
from neutron.openstack.common import importutils
from neutron.openstack.common import log as logging
from oslo.config import cfg
import webob

from quark.db import api as db_api
from quark import exceptions as quark_exceptions
from quark import plugin_views as v


CONF = cfg.CONF
LOG = logging.getLogger(__name__)
ipam_driver = (importutils.import_class(CONF.QUARK.ipam_driver))()


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


def create_ip_address(context, ip_address):
    LOG.info("create_ip_address for tenant %s" % context.tenant_id)

    port = None
    ip_dict = ip_address["ip_address"]
    port_ids = ip_dict.get('port_ids')
    network_id = ip_dict.get('network_id')
    device_ids = ip_dict.get('device_ids')
    ip_version = ip_dict.get('version')
    ip_address = ip_dict.get('ip_address')

    ports = []
    if device_ids and not network_id:
        raise exceptions.BadRequest(
            resource="ip_addresses",
            msg="network_id is required if device_ids are supplied.")
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

        address = ipam_driver.allocate_ip_address(
            context,
            port['network_id'],
            port['id'],
            CONF.QUARK.ipam_reuse_after,
            ip_version,
            ip_addresses=[ip_address])

        for port in ports:
            port["ip_addresses"].append(address)

    return v._make_ip_dict(address)


def _get_deallocated_override():
    """This function exists to mock and for future requirements if needed."""
    return '2000-01-01 00:00:00'


def update_ip_address(context, id, ip_address):
    LOG.info("update_ip_address %s for tenant %s" %
             (id, context.tenant_id))

    with context.session.begin():
        address = db_api.ip_address_find(
            context, id=id, tenant_id=context.tenant_id, scope=db_api.ONE)

        if not address:
            raise exceptions.NotFound(
                message="No IP address found with id=%s" % id)

        reset = ip_address['ip_address'].get('reset_allocation_time',
                                             False)
        if reset and address['deallocated'] == 1:
            if context.is_admin:
                LOG.info("IP's deallocated time being manually reset")
                address['deallocated_at'] = _get_deallocated_override()
            else:
                msg = "Modification of reset_allocation_time requires admin"
                raise webob.exc.HTTPForbidden(detail=msg)

        old_ports = address['ports']
        port_ids = ip_address['ip_address'].get('port_ids')
        if port_ids is None:
            return v._make_ip_dict(address)

        for port in old_ports:
            port['ip_addresses'].remove(address)

        if port_ids:
            ports = db_api.port_find(
                context, tenant_id=context.tenant_id, id=port_ids,
                scope=db_api.ALL)

            # NOTE: could be considered inefficient because we're converting
            #       to a list to check length. Maybe revisit
            if len(ports) != len(port_ids):
                raise exceptions.NotFound(
                    message="No ports not found with ids=%s" % port_ids)
            for port in ports:
                port['ip_addresses'].extend([address])
        else:
            address["deallocated"] = 1

    return v._make_ip_dict(address)
