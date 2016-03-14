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
from oslo_config import cfg
from oslo_log import log as logging

from quark.db import api as db_api
from quark.db import ip_types
from quark.drivers import floating_ip_registry as registry
from quark import exceptions as qex
from quark import ipam
from quark import plugin_views as v


CONF = cfg.CONF
LOG = logging.getLogger(__name__)

quark_router_opts = [
    cfg.StrOpt('floating_ip_segment_name', default='floating_ip',
               help=_('Segment name for floating IP subnets')),
    cfg.StrOpt('floating_ip_ipam_strategy', default='ANY',
               help=_('Override the network IPAM stategy for floating '
                      "allocation. Use 'NETWORK' to fall back to the "
                      "network's strategy")),
]

CONF.register_opts(quark_router_opts, 'QUARK')


def create_floatingip(context, content):
    """Allocate or reallocate a floating IP.

    :param context: neutron api request context.
    :param content: dictionary describing the floating ip, with keys
        as listed in the RESOURCE_ATTRIBUTE_MAP object in
        neutron/api/v2/attributes.py.  All keys will be populated.

    :returns: Dictionary containing details for the new floating IP.  If values
        are declared in the fields parameter, then only those keys will be
        present.
    """
    LOG.info('create_floatingip %s for tenant %s and body %s' %
             (id, context.tenant_id, content))
    tenant_id = content.get('tenant_id')
    network_id = content.get('floating_network_id')
    fixed_ip_address = content.get('fixed_ip_address')
    ip_address = content.get('floating_ip_address')
    port_id = content.get('port_id')

    if not tenant_id:
        tenant_id = context.tenant_id

    if not network_id:
        raise exceptions.BadRequest(resource='floating_ip',
                                    msg='floating_network_id is required.')

    network = db_api.network_find(context, id=network_id, scope=db_api.ONE)

    if not network:
        raise exceptions.NetworkNotFound(net_id=network_id)

    fixed_ip = None
    port = None
    if port_id:
        port = db_api.port_find(context, id=port_id, scope=db_api.ONE)

        if not port:
            raise exceptions.PortNotFound(port_id=port_id)

        if not port.ip_addresses or len(port.ip_addresses) == 0:
            raise qex.NoAvailableFixedIpsForPort(port_id=port_id)

        if not fixed_ip_address:
            fixed_ip = _get_next_available_fixed_ip(port)
            if not fixed_ip:
                raise qex.NoAvailableFixedIpsForPort(
                    port_id=port_id)
        else:
            fixed_ip = next((ip for ip in port.ip_addresses
                            if (ip['address_readable'] == fixed_ip_address and
                                ip.get('address_type') == ip_types.FIXED)),
                            None)

            if not fixed_ip:
                raise qex.FixedIpDoesNotExistsForPort(
                    fixed_ip=fixed_ip_address, port_id=port_id)

            if any(ip for ip in port.ip_addresses
                   if (ip.get('address_type') == ip_types.FLOATING and
                       ip.fixed_ip['address_readable'] == fixed_ip_address)):
                raise qex.PortAlreadyContainsFloatingIp(
                    port_id=port_id)

    new_addresses = []
    ip_addresses = []
    if ip_address:
        ip_addresses.append(ip_address)

    seg_name = CONF.QUARK.floating_ip_segment_name
    strategy_name = CONF.QUARK.floating_ip_ipam_strategy

    if strategy_name.upper() == 'NETWORK':
        strategy_name = network.get("ipam_strategy")

    ipam_driver = ipam.IPAM_REGISTRY.get_strategy(strategy_name)
    ipam_driver.allocate_ip_address(context, new_addresses, network_id,
                                    port_id, CONF.QUARK.ipam_reuse_after,
                                    seg_name, version=4,
                                    ip_addresses=ip_addresses,
                                    address_type=ip_types.FLOATING)

    flip = new_addresses[0]

    if fixed_ip and port:
        context.session.begin()
        try:
            flip = db_api.port_associate_ip(context, [port], flip, [port_id])
            flip = db_api.floating_ip_associate_fixed_ip(context, flip,
                                                         fixed_ip)

            flip_driver = registry.DRIVER_REGISTRY.get_driver()

            flip_driver.register_floating_ip(flip, port, fixed_ip)
            context.session.commit()
        except Exception:
            context.session.rollback()
            raise

    return v._make_floating_ip_dict(flip, port_id)


def update_floatingip(context, id, content):
    """Update an existing floating IP.

    :param context: neutron api request context.
    :param id: id of the floating ip
    :param content: dictionary with keys indicating fields to update.
        valid keys are those that have a value of True for 'allow_put'
        as listed in the RESOURCE_ATTRIBUTE_MAP object in
        neutron/api/v2/attributes.py.

    :returns: Dictionary containing details for the new floating IP.  If values
        are declared in the fields parameter, then only those keys will be
        present.
    """

    LOG.info('update_floatingip %s for tenant %s and body %s' %
             (id, context.tenant_id, content))

    if 'port_id' not in content:
        raise exceptions.BadRequest(resource='floating_ip',
                                    msg='port_id is required.')

    port_id = content.get('port_id')
    port = None
    fixed_ip = None
    current_port = None

    context.session.begin()
    try:
        flip = db_api.floating_ip_find(context, id=id, scope=db_api.ONE)
        if not flip:
            raise qex.FloatingIpNotFound(id=id)

        current_ports = flip.ports

        if current_ports and len(current_ports) > 0:
            current_port = current_ports[0]

        if not port_id and not current_port:
            raise qex.FloatingIpUpdateNoPortIdSupplied()

        if port_id:
            port = db_api.port_find(context, id=port_id, scope=db_api.ONE)
            if not port:
                raise exceptions.PortNotFound(port_id=port_id)

            if any(ip for ip in port.ip_addresses
                   if (ip.get('address_type') == ip_types.FLOATING)):
                raise qex.PortAlreadyContainsFloatingIp(port_id=port_id)

            if current_port and current_port.id == port_id:
                d = dict(flip_id=id, port_id=port_id)
                raise qex.PortAlreadyAssociatedToFloatingIp(**d)

            fixed_ip = _get_next_available_fixed_ip(port)
            LOG.info('new fixed ip: %s' % fixed_ip)
            if not fixed_ip:
                raise qex.NoAvailableFixedIpsForPort(port_id=port_id)

        LOG.info('current ports: %s' % current_ports)

        if current_port:
            flip = db_api.port_disassociate_ip(context, [current_port], flip)

        if flip.fixed_ip:
            flip = db_api.floating_ip_disassociate_fixed_ip(context, flip)

        if port:
            flip = db_api.port_associate_ip(context, [port], flip, [port_id])
            flip = db_api.floating_ip_associate_fixed_ip(context, flip,
                                                         fixed_ip)

        flip_driver = registry.DRIVER_REGISTRY.get_driver()

        if port:
            if current_port:
                flip_driver.update_floating_ip(flip, port, fixed_ip)
            else:
                flip_driver.register_floating_ip(flip, port, fixed_ip)
        else:
            flip_driver.remove_floating_ip(flip)

        context.session.commit()
    except (qex.RegisterFloatingIpFailure, qex.RemoveFloatingIpFailure):
        context.session.rollback()
        raise

    # Note(alanquillin) The ports parameters on the model is not
    # properly getting cleaned up when removed.  Manually cleaning them up.
    # Need to fix the db api to correctly update the model.
    if not port:
        flip.ports = []

    return v._make_floating_ip_dict(flip, port_id)


def delete_floatingip(context, id):
    """deallocate a floating IP.

    :param context: neutron api request context.
    :param id: id of the floating ip
    """

    LOG.info('delete_floatingip %s for tenant %s' % (id, context.tenant_id))

    filters = {'address_type': ip_types.FLOATING, '_deallocated': False}

    flip = db_api.floating_ip_find(context, id=id, scope=db_api.ONE, **filters)
    if not flip:
        raise qex.FloatingIpNotFound(id=id)

    current_ports = flip.ports
    current_port = None

    if current_ports and len(current_ports) > 0:
        current_port = current_ports[0]

    context.session.begin()
    try:
        strategy_name = flip.network.get('ipam_strategy')
        ipam_driver = ipam.IPAM_REGISTRY.get_strategy(strategy_name)
        ipam_driver.deallocate_ip_address(context, flip)

        if current_port:
            flip = db_api.port_disassociate_ip(context, [current_port],
                                               flip)
        if flip.fixed_ip:
            flip = db_api.floating_ip_disassociate_fixed_ip(context, flip)

        context.session.commit()
    except Exception:
        context.session.rollback()
        raise

    try:
        driver = registry.DRIVER_REGISTRY.get_driver()
        driver.remove_floating_ip(flip)
    except Exception as e:
        LOG.error('There was an error when trying to delete the floating ip '
                  'on the unicorn API.  The ip has been cleaned up, but '
                  'may need to be handled manually in the unicorn API.  '
                  'Error: %s' % e.message)


def get_floatingip(context, id, fields=None):
    """Retrieve a floating IP.

    :param context: neutron api request context.
    :param id: The UUID of the floating IP.
    :param fields: a list of strings that are valid keys in a
        floating IP dictionary as listed in the RESOURCE_ATTRIBUTE_MAP
        object in neutron/api/v2/attributes.py. Only these fields
        will be returned.

    :returns: Dictionary containing details for the floating IP.  If values
        are declared in the fields parameter, then only those keys will be
        present.
    """
    LOG.info('get_floatingip %s for tenant %s' % (id, context.tenant_id))

    filters = {'address_type': ip_types.FLOATING, '_deallocated': False}

    floating_ip = db_api.floating_ip_find(context, id=id, scope=db_api.ONE,
                                          **filters)

    if not floating_ip:
        raise qex.FloatingIpNotFound(id=id)

    return v._make_floating_ip_dict(floating_ip)


def get_floatingips(context, filters=None, fields=None, sorts=None, limit=None,
                    marker=None, page_reverse=False):
    """Retrieve a list of floating ips.

    :param context: neutron api request context.
    :param filters: a dictionary with keys that are valid keys for
        a floating ip as listed in the RESOURCE_ATTRIBUTE_MAP object
        in neutron/api/v2/attributes.py.  Values in this dictionary
        are an iterable containing values that will be used for an exact
        match comparison for that value.  Each result returned by this
        function will have matched one of the values for each key in
        filters.
    :param fields: a list of strings that are valid keys in a
        floating IP dictionary as listed in the RESOURCE_ATTRIBUTE_MAP
        object in neutron/api/v2/attributes.py. Only these fields
        will be returned.

    :returns: List of floating IPs that are accessible to the tenant who
        submits the request (as indicated by the tenant id of the context)
        as well as any filters.
    """
    LOG.info('get_floatingips for tenant %s filters %s fields %s' %
             (context.tenant_id, filters, fields))

    if filters is None:
        filters = {}

    filters['_deallocated'] = False
    filters['address_type'] = ip_types.FLOATING

    floating_ips = db_api.floating_ip_find(context, scope=db_api.ALL,
                                           **filters)

    return [v._make_floating_ip_dict(flip) for flip in floating_ips]


def get_floatingips_count(context, filters=None):
    """Return the number of floating IPs.

    :param context: neutron api request context
    :param filters: a dictionary with keys that are valid keys for
        a floating IP as listed in the RESOURCE_ATTRIBUTE_MAP object
        in neutron/api/v2/attributes.py.  Values in this dictionary
        are an iterable containing values that will be used for an exact
        match comparison for that value.  Each result returned by this
        function will have matched one of the values for each key in
        filters.

    :returns: The number of floating IPs that are accessible to the tenant who
        submits the request (as indicated by the tenant id of the context)
        as well as any filters.

    NOTE: this method is optional, as it was not part of the originally
          defined plugin API.
    """
    LOG.info('get_floatingips_count for tenant %s filters %s' %
             (context.tenant_id, filters))

    if filters is None:
        filters = {}

    filters['_deallocated'] = False
    filters['address_type'] = ip_types.FLOATING
    count = db_api.ip_address_count_all(context, filters)

    LOG.info('Found %s floating ips for tenant %s' % (count,
                                                      context.tenant_id))
    return count


def _get_next_available_fixed_ip(port):
    floating_ips = [ip for ip in port.ip_addresses
                    if ip.get('address_type') == ip_types.FLOATING]
    fixed_ips = [ip for ip in port.ip_addresses
                 if ip.get('address_type') == ip_types.FIXED]

    if not fixed_ips or len(fixed_ips) == 0:
        return None

    used = [ip.fixed_ip.address for ip in floating_ips
            if ip and ip.fixed_ip]

    return next((ip for ip in sorted(fixed_ips,
                                     key=lambda ip: ip.get('allocated_at'))
                if ip.address not in used), None)
