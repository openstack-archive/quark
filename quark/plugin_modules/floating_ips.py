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

from quark import billing
from quark.db import api as db_api
from quark.db import ip_types
from quark.drivers import floating_ip_registry as registry
from quark import exceptions as q_exc
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


def _get_network(context, network_id):
    network = db_api.network_find(context, id=network_id, scope=db_api.ONE)
    if not network:
        raise n_exc.NetworkNotFound(net_id=network_id)
    return network


def _get_port(context, port_id):
    port = db_api.port_find(context, id=port_id, scope=db_api.ONE)
    if not port:
        raise n_exc.PortNotFound(port_id=port_id)

    if not port.ip_addresses or len(port.ip_addresses) == 0:
        raise q_exc.NoAvailableFixedIpsForPort(port_id=port_id)
    return port


def _get_fixed_ip(context, given_fixed_ip, port):
    if not given_fixed_ip:
        fixed_ip = _get_next_available_fixed_ip(port)
        if not fixed_ip:
            raise q_exc.NoAvailableFixedIpsForPort(
                port_id=port.id)
    else:
        fixed_ip = next((ip for ip in port.ip_addresses
                        if (ip['address_readable'] == given_fixed_ip and
                            ip.get('address_type') == ip_types.FIXED)),
                        None)

        if not fixed_ip:
            raise q_exc.FixedIpDoesNotExistsForPort(
                fixed_ip=given_fixed_ip, port_id=port.id)

        if any(ip for ip in port.ip_addresses
               if (ip.get('address_type') in (ip_types.FLOATING,
                                              ip_types.SCALING) and
                   ip.fixed_ip['address_readable'] == given_fixed_ip)):
            raise q_exc.PortAlreadyContainsFloatingIp(
                port_id=port.id)
    return fixed_ip


def _allocate_ip(context, network, port, requested_ip_address, address_type):
    new_addresses = []
    ip_addresses = []
    if requested_ip_address:
        ip_addresses.append(requested_ip_address)

    seg_name = CONF.QUARK.floating_ip_segment_name
    strategy_name = CONF.QUARK.floating_ip_ipam_strategy

    if strategy_name.upper() == 'NETWORK':
        strategy_name = network.get("ipam_strategy")

    port_id = port
    if port:
        port_id = port.id

    ipam_driver = ipam.IPAM_REGISTRY.get_strategy(strategy_name)
    ipam_driver.allocate_ip_address(context, new_addresses, network.id,
                                    port_id, CONF.QUARK.ipam_reuse_after,
                                    seg_name, version=4,
                                    ip_addresses=ip_addresses,
                                    address_type=address_type)

    return new_addresses[0]


def _get_next_available_fixed_ip(port):
    floating_ips = [ip for ip in port.ip_addresses
                    if ip.get('address_type') in
                    (ip_types.FLOATING, ip_types.SCALING)]
    fixed_ips = [ip for ip in port.ip_addresses
                 if ip.get('address_type') == ip_types.FIXED]

    if not fixed_ips or len(fixed_ips) == 0:
        return None

    used = [ip.fixed_ip.address for ip in floating_ips
            if ip and ip.fixed_ip]

    return next((ip for ip in sorted(fixed_ips,
                                     key=lambda ip: ip.get('allocated_at'))
                if ip.address not in used), None)


def _get_ips_by_type(context, ip_type, filters=None, fields=None):
    filters = filters or {}
    filters['_deallocated'] = False
    filters['address_type'] = ip_type
    ips = db_api.floating_ip_find(context, scope=db_api.ALL, **filters)
    return ips


def _create_flip(context, flip, port_fixed_ips):
    """Associates the flip with ports and creates it with the flip driver

    :param context: neutron api request context.
    :param flip: quark.db.models.IPAddress object representing a floating IP
    :param port_fixed_ips: dictionary of the structure:
    {"<id of port>": {"port": <quark.db.models.Port>,
     "fixed_ip": "<fixed ip address>"}}
    :return: None
    """
    if port_fixed_ips:
        context.session.begin()
        try:
            ports = [val['port'] for val in port_fixed_ips.values()]
            flip = db_api.port_associate_ip(context, ports, flip,
                                            port_fixed_ips.keys())

            for port_id in port_fixed_ips:
                fixed_ip = port_fixed_ips[port_id]['fixed_ip']
                flip = db_api.floating_ip_associate_fixed_ip(context, flip,
                                                             fixed_ip)

            flip_driver = registry.DRIVER_REGISTRY.get_driver()

            flip_driver.register_floating_ip(flip, port_fixed_ips)
            context.session.commit()
        except Exception:
            context.session.rollback()
            raise

    # alexm: Notify from this method for consistency with _delete_flip
    billing.notify(context, 'ip.associate', flip)


def _get_flip_fixed_ip_by_port_id(flip, port_id):
    for fixed_ip in flip.fixed_ips:
        if fixed_ip.ports[0].id == port_id:
            return fixed_ip


def _update_flip(context, flip_id, ip_type, requested_ports):
    """Update a flip based IPAddress

    :param context: neutron api request context.
    :param flip_id: id of the flip or scip
    :param ip_type: ip_types.FLOATING | ip_types.SCALING
    :param requested_ports: dictionary of the structure:
    {"port_id": "<id of port>", "fixed_ip": "<fixed ip address>"}
    :return: quark.models.IPAddress
    """
    # This list will hold flips that require notifications.
    # Using sets to avoid dups, if any.
    notifications = {
        'ip.associate': set(),
        'ip.disassociate': set()
    }

    context.session.begin()
    try:
        flip = db_api.floating_ip_find(context, id=flip_id, scope=db_api.ONE)
        if not flip:
            if ip_type == ip_types.SCALING:
                raise q_exc.ScalingIpNotFound(id=flip_id)
            raise q_exc.FloatingIpNotFound(id=flip_id)
        current_ports = flip.ports

        # Determine what ports are being removed, being added, and remain
        req_port_ids = [request_port.get('port_id')
                        for request_port in requested_ports]
        curr_port_ids = [curr_port.id for curr_port in current_ports]
        added_port_ids = [port_id for port_id in req_port_ids
                          if port_id and port_id not in curr_port_ids]
        removed_port_ids = [port_id for port_id in curr_port_ids
                            if port_id not in req_port_ids]
        remaining_port_ids = set(curr_port_ids) - set(removed_port_ids)

        # Validations just for floating ip types
        if (ip_type == ip_types.FLOATING and curr_port_ids and
                curr_port_ids == req_port_ids):
            d = dict(flip_id=flip_id, port_id=curr_port_ids[0])
            raise q_exc.PortAlreadyAssociatedToFloatingIp(**d)
        if (ip_type == ip_types.FLOATING and
                not curr_port_ids and not req_port_ids):
            raise q_exc.FloatingIpUpdateNoPortIdSupplied()

        port_fixed_ips = {}

        # Keep the ports and fixed ips that have not changed
        for port_id in remaining_port_ids:
            port = db_api.port_find(context, id=port_id, scope=db_api.ONE)
            fixed_ip = _get_flip_fixed_ip_by_port_id(flip, port_id)
            port_fixed_ips[port_id] = {'port': port, 'fixed_ip': fixed_ip}

        # Disassociate the ports and fixed ips from the flip that were
        # associated to the flip but are not anymore
        for port_id in removed_port_ids:
            port = db_api.port_find(context, id=port_id, scope=db_api.ONE)
            flip = db_api.port_disassociate_ip(context, [port], flip)
            notifications['ip.disassociate'].add(flip)
            fixed_ip = _get_flip_fixed_ip_by_port_id(flip, port_id)
            if fixed_ip:
                flip = db_api.floating_ip_disassociate_fixed_ip(
                    context, flip, fixed_ip)

        # Validate the new ports with the flip and associate the new ports
        # and fixed ips with the flip
        for port_id in added_port_ids:
            port = db_api.port_find(context, id=port_id, scope=db_api.ONE)
            if not port:
                raise n_exc.PortNotFound(port_id=port_id)
            if any(ip for ip in port.ip_addresses
                   if (ip.get('address_type') == ip_types.FLOATING)):
                raise q_exc.PortAlreadyContainsFloatingIp(port_id=port_id)
            if any(ip for ip in port.ip_addresses
                   if (ip.get('address_type') == ip_types.SCALING)):
                raise q_exc.PortAlreadyContainsScalingIp(port_id=port_id)
            fixed_ip = _get_next_available_fixed_ip(port)
            LOG.info('new fixed ip: %s' % fixed_ip)
            if not fixed_ip:
                raise q_exc.NoAvailableFixedIpsForPort(port_id=port_id)
            port_fixed_ips[port_id] = {'port': port, 'fixed_ip': fixed_ip}
            flip = db_api.port_associate_ip(context, [port], flip, [port_id])
            notifications['ip.associate'].add(flip)
            flip = db_api.floating_ip_associate_fixed_ip(context, flip,
                                                         fixed_ip)

        flip_driver = registry.DRIVER_REGISTRY.get_driver()
        # If there are not any remaining ports and no new ones are being added,
        # remove the floating ip from unicorn
        if not remaining_port_ids and not added_port_ids:
            flip_driver.remove_floating_ip(flip)
        # If new ports are being added but there previously was not any ports,
        # then register a new floating ip with the driver because it is
        # assumed it does not exist
        elif added_port_ids and not curr_port_ids:
            flip_driver.register_floating_ip(flip, port_fixed_ips)
        else:
            flip_driver.update_floating_ip(flip, port_fixed_ips)
        context.session.commit()
    except Exception:
        context.session.rollback()
        raise

    # Send notifications for possible associate/disassociate events
    for notif_type, flip_set in notifications.iteritems():
        for flip in flip_set:
            billing.notify(context, notif_type, flip)

    # NOTE(blogan): ORM does not seem to update the model to the real state
    # of the database, so I'm doing an explicit refresh for now.
    context.session.refresh(flip)
    return flip


def _delete_flip(context, id, address_type):
    filters = {'address_type': address_type, '_deallocated': False}

    flip = db_api.floating_ip_find(context, id=id, scope=db_api.ONE, **filters)
    if not flip:
        raise q_exc.FloatingIpNotFound(id=id)

    current_ports = flip.ports
    if address_type == ip_types.FLOATING:
        if current_ports:
            current_ports = [flip.ports[0]]
    elif address_type == ip_types.SCALING:
        current_ports = flip.ports

    context.session.begin()
    try:
        strategy_name = flip.network.get('ipam_strategy')
        ipam_driver = ipam.IPAM_REGISTRY.get_strategy(strategy_name)
        ipam_driver.deallocate_ip_address(context, flip)

        if current_ports:
            db_api.port_disassociate_ip(context, current_ports, flip)
        if flip.fixed_ips:
            db_api.floating_ip_disassociate_all_fixed_ips(context, flip)

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

    # alexm: Notify from this method because we don't have the flip object
    # in the callers
    billing.notify(context, 'ip.disassociate', flip)


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
    network_id = content.get('floating_network_id')
    # TODO(blogan): Since the extension logic will reject any requests without
    # floating_network_id, is this still needed?
    if not network_id:
        raise n_exc.BadRequest(resource='floating_ip',
                               msg='floating_network_id is required.')
    fixed_ip_address = content.get('fixed_ip_address')
    ip_address = content.get('floating_ip_address')
    port_id = content.get('port_id')
    port = None
    port_fixed_ip = {}

    network = _get_network(context, network_id)
    if port_id:
        port = _get_port(context, port_id)
        fixed_ip = _get_fixed_ip(context, fixed_ip_address, port)
        port_fixed_ip = {port.id: {'port': port, 'fixed_ip': fixed_ip}}
    flip = _allocate_ip(context, network, port, ip_address, ip_types.FLOATING)
    _create_flip(context, flip, port_fixed_ip)
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
        raise n_exc.BadRequest(resource='floating_ip',
                               msg='port_id is required.')

    requested_ports = []
    if content.get('port_id'):
        requested_ports = [{'port_id': content.get('port_id')}]
    flip = _update_flip(context, id, ip_types.FLOATING, requested_ports)
    return v._make_floating_ip_dict(flip)


def delete_floatingip(context, id):
    """deallocate a floating IP.

    :param context: neutron api request context.
    :param id: id of the floating ip
    """

    LOG.info('delete_floatingip %s for tenant %s' % (id, context.tenant_id))

    _delete_flip(context, id, ip_types.FLOATING)


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
        raise q_exc.FloatingIpNotFound(id=id)

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

    floating_ips = _get_ips_by_type(context, ip_types.FLOATING,
                                    filters=filters, fields=fields)

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


def create_scalingip(context, content):
    """Allocate or reallocate a scaling IP.

    :param context: neutron api request context.
    :param content: dictionary describing the scaling ip, with keys
        as listed in the RESOURCE_ATTRIBUTE_MAP object in
        neutron/api/v2/attributes.py.  All keys will be populated.

    :returns: Dictionary containing details for the new scaling IP.  If values
        are declared in the fields parameter, then only those keys will be
        present.
    """
    LOG.info('create_scalingip for tenant %s and body %s',
             context.tenant_id, content)
    network_id = content.get('scaling_network_id')
    ip_address = content.get('scaling_ip_address')
    requested_ports = content.get('ports', [])

    network = _get_network(context, network_id)
    port_fixed_ips = {}
    for req_port in requested_ports:
        port = _get_port(context, req_port['port_id'])
        fixed_ip = _get_fixed_ip(context, req_port.get('fixed_ip_address'),
                                 port)
        port_fixed_ips[port.id] = {"port": port, "fixed_ip": fixed_ip}
    scip = _allocate_ip(context, network, None, ip_address, ip_types.SCALING)
    _create_flip(context, scip, port_fixed_ips)
    return v._make_scaling_ip_dict(scip)


def update_scalingip(context, id, content):
    """Update an existing scaling IP.

    :param context: neutron api request context.
    :param id: id of the scaling ip
    :param content: dictionary with keys indicating fields to update.
        valid keys are those that have a value of True for 'allow_put'
        as listed in the RESOURCE_ATTRIBUTE_MAP object in
        neutron/api/v2/attributes.py.

    :returns: Dictionary containing details for the new scaling IP.  If values
        are declared in the fields parameter, then only those keys will be
        present.
    """
    LOG.info('update_scalingip %s for tenant %s and body %s' %
             (id, context.tenant_id, content))
    requested_ports = content.get('ports', [])
    flip = _update_flip(context, id, ip_types.SCALING, requested_ports)
    return v._make_scaling_ip_dict(flip)


def delete_scalingip(context, id):
    """Deallocate a scaling IP.

    :param context: neutron api request context.
    :param id: id of the scaling ip
    """
    LOG.info('delete_scalingip %s for tenant %s' % (id, context.tenant_id))
    _delete_flip(context, id, ip_types.SCALING)


def get_scalingip(context, id, fields=None):
    """Retrieve a scaling IP.

    :param context: neutron api request context.
    :param id: The UUID of the scaling IP.
    :param fields: a list of strings that are valid keys in a
        scaling IP dictionary as listed in the RESOURCE_ATTRIBUTE_MAP
        object in neutron/api/v2/attributes.py. Only these fields
        will be returned.

    :returns: Dictionary containing details for the scaling IP.  If values
        are declared in the fields parameter, then only those keys will be
        present.
    """
    LOG.info('get_scalingip %s for tenant %s' % (id, context.tenant_id))
    filters = {'address_type': ip_types.SCALING, '_deallocated': False}
    scaling_ip = db_api.floating_ip_find(context, id=id, scope=db_api.ONE,
                                         **filters)
    if not scaling_ip:
        raise q_exc.ScalingIpNotFound(id=id)
    return v._make_scaling_ip_dict(scaling_ip)


def get_scalingips(context, filters=None, fields=None, sorts=None, limit=None,
                   marker=None, page_reverse=False):
    """Retrieve a list of scaling ips.

    :param context: neutron api request context.
    :param filters: a dictionary with keys that are valid keys for
        a scaling ip as listed in the RESOURCE_ATTRIBUTE_MAP object
        in neutron/api/v2/attributes.py.  Values in this dictionary
        are an iterable containing values that will be used for an exact
        match comparison for that value.  Each result returned by this
        function will have matched one of the values for each key in
        filters.
    :param fields: a list of strings that are valid keys in a
        scaling IP dictionary as listed in the RESOURCE_ATTRIBUTE_MAP
        object in neutron/api/v2/attributes.py. Only these fields
        will be returned.

    :returns: List of scaling IPs that are accessible to the tenant who
        submits the request (as indicated by the tenant id of the context)
        as well as any filters.
    """
    LOG.info('get_scalingips for tenant %s filters %s fields %s' %
             (context.tenant_id, filters, fields))
    scaling_ips = _get_ips_by_type(context, ip_types.SCALING,
                                   filters=filters, fields=fields)
    return [v._make_scaling_ip_dict(scip) for scip in scaling_ips]
