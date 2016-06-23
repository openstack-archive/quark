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

import datetime
import inspect

import json
import netaddr
from neutron.db.sqlalchemyutils import paginate_query
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import timeutils
from oslo_utils import uuidutils
from sqlalchemy import event
from sqlalchemy import func as sql_func
from sqlalchemy import and_, asc, desc, orm, or_, not_
from sqlalchemy.orm import class_mapper

from quark.db import models
from quark import network_strategy
from quark import protocols
from quark import tags

PORT_TAG_REGISTRY = tags.PORT_TAG_REGISTRY
STRATEGY = network_strategy.STRATEGY
LOG = logging.getLogger(__name__)
CONF = cfg.CONF


ONE = "one"
ALL = "all"

_NO_TENANT_MODELS = (
    models.PortIpAssociation,
    models.LockHolder,
    models.SegmentAllocationRange)


# NOTE(jkoelker) init event listener that will ensure id is filled in
#                on object creation (prior to commit).
def _perhaps_generate_id(target, args, kwargs):
    if hasattr(target, 'id') and target.id is None:
        target.id = uuidutils.generate_uuid()


# NOTE(jkoelker) Register the event on all models that have ids
for _name, klass in inspect.getmembers(models, inspect.isclass):
    if klass is models.HasId:
        continue

    if models.HasId in klass.mro():
        event.listen(klass, "init", _perhaps_generate_id)


def _listify(filters):
    for key in ["name", "network_id", "id", "device_id", "tenant_id",
                "subnet_id", "mac_address", "shared", "version", "segment_id",
                "device_owner", "ip_address", "used_by_tenant_id", "group_id"]:
        if key in filters:
            if not filters[key]:
                continue
            listified = filters[key]
            if not isinstance(listified, list):
                listified = [listified]
            filters[key] = listified


def _model_attrs(model):
    model_map = class_mapper(model)
    model_attrs = [x.key for x in model_map.column_attrs]
    if "_cidr" in model_attrs:
        model_attrs.append("cidr")
    if "_deallocated" in model_attrs:
        model_attrs.append("deallocated")
    return model_attrs


def _model_query(context, model, filters, fields=None):
    filters = filters or {}
    model_filters = []
    eq_filters = ["address", "cidr", "deallocated", "ip_version", "service",
                  "mac_address_range_id", "transaction_id", "lock_id",
                  "address_type", "completed"]
    in_filters = ["device_id", "device_owner", "group_id", "id", "mac_address",
                  "name", "network_id", "segment_id", "subnet_id",
                  "used_by_tenant_id", "version"]

    # Sanitize incoming filters to only attributes that exist in the model.
    # NOTE: Filters for unusable attributes are silently dropped here.
    # NOTE: When the filter key != attribute key, a conditional must be added
    #       here.
    model_attrs = _model_attrs(model)
    filters = {x: y for x, y in filters.items()
               if x in model_attrs or
               (x == "tenant_id" and model == models.IPAddress) or
               (x == "ip_address" and model == models.IPAddress) or
               (x == "reuse_after" and model in (models.IPAddress,
                                                 models.MacAddress))}

    # Inject the tenant id if none is set. We don't need unqualified queries.
    # This works even when a non-shared, other-tenant owned network is passed
    # in because the authZ checks that happen in Neutron above us yank it back
    # out of the result set.
    if not filters.get("tenant_id") and not context.is_admin:
        filters["tenant_id"] = [context.tenant_id]

    if model == models.SecurityGroupRule:
        sg_rule_attribs = ["direction", "port_range_max", "port_range_min"]
        eq_filters.extend(sg_rule_attribs)

    for key, value in filters.items():
        if key in in_filters:
            model_type = getattr(model, key)
            model_filters.append(model_type.in_(value))
        elif key in eq_filters:
            model_type = getattr(model, key)
            model_filters.append(model_type == value)
        elif key == "_deallocated":
            if value:
                model_filters.append(model._deallocated == 1)
            else:
                model_filters.append(model._deallocated != 1)
        elif key == "ethertype":
            etypes = []
            for etype in value:
                etypes.append(protocols.translate_ethertype(etype))
            model_filters.append(model.ethertype.in_(etypes))
        elif key == "ip_address":
            model_filters.append(model.address.in_(
                [ip.ipv6().value for ip in value]))
        elif key == 'protocol':
            pnums = []
            for version in (protocols.PROTOCOLS_V4, protocols.PROTOCOLS_V6):
                pnums.extend([y for x, y in version.items() if x in value])
            model_filters.append(model.protocol.in_(pnums))
        elif key == "reuse_after":
            reuse = (timeutils.utcnow() -
                     datetime.timedelta(seconds=value))
            # NOTE(asadoughi): should this allow for deallocated_at = null?
            model_filters.append(model.deallocated_at <= reuse)
        elif key == "port_id":
            if model == models.PortIpAssociation:
                model_filters.append(model.port_id == value)
        elif key == "tenant_id":
            if model == models.IPAddress:
                model_filters.append(model.used_by_tenant_id.in_(value))
            elif model in _NO_TENANT_MODELS:
                pass
            else:
                model_filters.append(model.tenant_id.in_(value))

    return model_filters


def scoped(f):
    def wrapped(*args, **kwargs):
        scope = None
        if "scope" in kwargs:
            scope = kwargs.pop("scope")
        if scope not in [None, ALL, ONE]:
            raise Exception("Invalid scope")
        _listify(kwargs)

        res = f(*args, **kwargs)
        if not res:
            return
        if "order_by" in kwargs:
            res = res.order_by(kwargs["order_by"])

        if scope == ALL:
            if isinstance(res, list):
                return res
            return res.all()
        elif scope == ONE:
            if isinstance(res, list):
                return res[0]
            return res.first()
        return res
    return wrapped


@scoped
def port_find(context, limit=None, sorts=None, marker_obj=None, fields=None,
              **filters):
    query = context.session.query(models.Port).options(
        orm.joinedload(models.Port.ip_addresses))
    model_filters = _model_query(context, models.Port, filters)
    if filters.get("ip_address_id"):
        model_filters.append(models.Port.ip_addresses.any(
            models.IPAddress.id.in_(filters["ip_address_id"])))

    if filters.get("device_id"):
        model_filters.append(models.Port.device_id.in_(filters["device_id"]))

    if filters.get("service"):
        model_filters.append(models.Port.associations.any(
            models.PortIpAssociation.service == filters["service"]))

    if "join_security_groups" in filters:
        query = query.options(orm.joinedload(models.Port.security_groups))

    if fields and "port_subnets" in fields:
        query = query.options(orm.joinedload("ip_addresses.subnet"))
        query = query.options(
            orm.joinedload("ip_addresses.subnet.dns_nameservers"))
        query = query.options(
            orm.joinedload("ip_addresses.subnet.routes"))
    return paginate_query(query.filter(*model_filters), models.Port, limit,
                          sorts, marker_obj)


@scoped
def port_find_by_ip_address(context, **filters):
    query = context.session.query(models.IPAddress).options(
        orm.joinedload(models.IPAddress.ports))
    model_filters = _model_query(context, models.IPAddress, filters)
    return query.filter(*model_filters)


def port_count_all(context, **filters):
    query = context.session.query(sql_func.count(models.Port.id))
    model_filters = _model_query(context, models.Port, filters)
    return query.filter(*model_filters).scalar()


def port_create(context, **port_dict):
    port = models.Port(tags=[])
    port.update(port_dict)
    port["tenant_id"] = context.tenant_id
    if "addresses" in port_dict:
        port["ip_addresses"].extend(port_dict["addresses"])
    PORT_TAG_REGISTRY.set_all(port, **port_dict)
    context.session.add(port)
    return port


@scoped
def ip_port_association_find(context, **filters):
    query = context.session.query(models.PortIpAssociation)
    model_filters = _model_query(context, models.PortIpAssociation, filters)
    return query.filter(*model_filters)


def port_disassociate_ip(context, ports, address):
    assocs_to_remove = [assoc for assoc in address.associations
                        if assoc.port in ports]
    for assoc in assocs_to_remove:
        context.session.delete(assoc)
        # NOTE(thomasem): Need to update in-session model for caller.
        address.associations.remove(assoc)
    context.session.add(address)
    return address


def port_associate_ip(context, ports, address, enable_port=None):
    for port in ports:
        assoc = models.PortIpAssociation()
        assoc.port = port
        assoc.ip_address = address
        assoc.enabled = port.id in enable_port if enable_port else False
        context.session.add(assoc)
    return address


def get_ports_for_address(address):
    ports = []
    for assoc in address.associations:
        ports.append(assoc.port)
    return ports


def update_port_associations_for_ip(context, ports, address):
    assoc_ports = set(get_ports_for_address(address))
    new_ports = set(ports)
    new_address = port_associate_ip(context, new_ports - assoc_ports,
                                    address)
    return port_disassociate_ip(context,
                                assoc_ports - new_ports, new_address)


def port_update(context, port, **kwargs):
    if "addresses" in kwargs:
        port["ip_addresses"] = kwargs.pop("addresses")
    PORT_TAG_REGISTRY.set_all(port, **kwargs)
    port.update(kwargs)
    context.session.add(port)
    return port


def port_delete(context, port):
    context.session.delete(port)


def ip_address_update(context, address, **kwargs):
    address.update(kwargs)
    context.session.add(address)
    return address


def ip_address_create(context, **address_dict):
    ip_address = models.IPAddress()
    address = address_dict.pop("address")
    ip_address.update(address_dict)
    ip_address["address"] = int(address.ipv6())
    ip_address["address_readable"] = str(address)
    ip_address["used_by_tenant_id"] = context.tenant_id
    ip_address["_deallocated"] = 0
    ip_address["allocated_at"] = timeutils.utcnow()
    context.session.add(ip_address)
    return ip_address


def ip_address_delete(context, addr):
    context.session.delete(addr)


def ip_address_deallocate(context, address, **kwargs):
    kwargs["_deallocated"] = 1
    kwargs["deallocated_at"] = timeutils.utcnow()
    return ip_address_update(context, address, **kwargs)


@scoped
def ip_address_find(context, lock_mode=False, **filters):
    query = context.session.query(models.IPAddress)

    if lock_mode:
        query = query.with_lockmode("update")

    # NOTE(asadoughi): NCP-1677: Maps string or integer into integer value
    if filters.get("address"):
        filters["address"] = int(netaddr.IPAddress(filters["address"]).ipv6())

    model_filters = _model_query(context, models.IPAddress, filters)

    if filters.get("device_id"):
        model_filters.append(models.IPAddress.ports.any(
            models.Port.device_id.in_(filters["device_id"])))

    if filters.get("service"):
        model_filters.append(models.IPAddress.associations.any(
            models.PortIpAssociation.service == filters["service"]))

    if filters.get("port_id"):
        model_filters.append(models.IPAddress.ports.any(
            models.Port.id == filters['port_id']))

    return query.filter(*model_filters)


def ip_address_count_all(context, filters):
    query = context.session.query(sql_func.count(models.IPAddress.id))
    model_filters = _model_query(context, models.IPAddress, filters)
    return query.filter(*model_filters).scalar()


@scoped
def ip_address_reallocate(context, update_kwargs, **filters):
    LOG.debug("ip_address_reallocate %s", filters)
    query = context.session.query(models.IPAddress)
    model_filters = _model_query(context, models.IPAddress, filters)
    query = query.filter(*model_filters)
    row_count = query.update(update_kwargs,
                             update_args={"mysql_limit": 1},
                             synchronize_session=False)
    return row_count == 1


def ip_address_reallocate_find(context, transaction_id):
    address = ip_address_find(context, transaction_id=transaction_id,
                              scope=ONE)
    if not address:
        LOG.warn("Couldn't find IP address with transaction_id %s",
                 transaction_id)
        return

    LOG.info("Potentially reallocatable IP found: "
             "{0}".format(address["address_readable"]))
    subnet = address.get('subnet')
    if not subnet:
        LOG.debug("No subnet associated with address")
        return
    if subnet["do_not_use"]:
        LOG.debug("Subnet marked as do_not_use")
        return

    addr = netaddr.IPAddress(int(address["address"]))
    if address["subnet"]["ip_version"] == 4:
        addr = addr.ipv4()
    else:
        addr = addr.ipv6()

    if subnet and subnet["ip_policy"]:
        policy = subnet["ip_policy"].get_cidrs_ip_set()
    else:
        policy = netaddr.IPSet([])

    if policy is not None and addr in policy:
        LOG.info("Deleting Address {0} due to policy "
                 "violation".format(
                     address["address_readable"]))
        context.session.delete(address)
        return

    # TODO(amir): performance test replacing this with SQL in
    #             ip_address_reallocate's UPDATE statement
    cidr = netaddr.IPNetwork(address["subnet"]["cidr"])
    if addr not in cidr:
        LOG.info("Address {0} isn't in the subnet "
                 "it claims to be in".format(
                     address["address_readable"]))
        context.session.delete(address)
        return

    return address


@scoped
def mac_address_find(context, lock_mode=False, **filters):
    query = context.session.query(models.MacAddress)
    if lock_mode:
        query = query.with_lockmode("update")
    model_filters = _model_query(context, models.MacAddress, filters)
    return query.filter(*model_filters)


def mac_address_delete(context, mac_address):
    context.session.delete(mac_address)


@scoped
def mac_address_reallocate(context, update_kwargs, **filters):
    LOG.debug("mac_address_reallocate %s", filters)
    query = context.session.query(models.MacAddress)
    model_filters = _model_query(context, models.MacAddress, filters)
    query = query.filter(*model_filters)
    row_count = query.update(update_kwargs, update_args={"mysql_limit": 1},
                             synchronize_session=False)
    return row_count == 1


def mac_address_reallocate_find(context, transaction_id):
    mac = mac_address_find(context, transaction_id=transaction_id,
                           scope=ONE)
    if not mac:
        LOG.warn("Couldn't find MAC address with transaction_id %s",
                 transaction_id)
        return

    # NOTE(mdietz): This is a HACK. Please see RM11043 for details
    if mac["mac_address_range"] and mac["mac_address_range"]["do_not_use"]:
        mac_address_delete(context, mac)
        LOG.debug("Found a deallocated MAC in a do_not_use"
                  " mac_address_range and deleted it. "
                  "Retrying...")
        return

    return mac


def mac_address_range_find_allocation_counts(context, address=None,
                                             use_forbidden_mac_range=False):
    count = sql_func.count(models.MacAddress.address)
    query = context.session.query(models.MacAddressRange,
                                  count.label("count")).with_lockmode("update")
    query = query.outerjoin(models.MacAddress)
    query = query.group_by(models.MacAddressRange.id)
    query = query.order_by(desc(count))
    if address:
        query = query.filter(models.MacAddressRange.last_address >= address)
        query = query.filter(models.MacAddressRange.first_address <= address)
    query = query.filter(models.MacAddressRange.next_auto_assign_mac != -1)
    if not use_forbidden_mac_range:
        query = query.filter(models.MacAddressRange.do_not_use == '0')  # noqa
    query = query.limit(1)
    return query.first()


@scoped
def mac_address_range_find(context, **filters):
    query = context.session.query(models.MacAddressRange)
    model_filters = _model_query(context, models.MacAddressRange, filters)
    return query.filter(*model_filters)


def mac_address_range_create(context, **range_dict):
    new_range = models.MacAddressRange()
    new_range.update(range_dict)
    context.session.add(new_range)
    return new_range


def mac_address_range_delete(context, mac_address_range):
    context.session.delete(mac_address_range)


def mac_address_range_update(context, mac_range, **kwargs):
    mac_range.update(kwargs)
    context.session.add(mac_range)
    return mac_range


def mac_range_update_next_auto_assign_mac(context, mac_range):
    query = context.session.query(models.MacAddressRange)
    query = query.filter(models.MacAddressRange.id == mac_range["id"])
    query = query.filter(models.MacAddressRange.next_auto_assign_mac != -1)

    # For details on synchronize_session, see:
    # http://docs.sqlalchemy.org/en/rel_0_8/orm/query.html
    query = query.update(
        {"next_auto_assign_mac":
         models.MacAddressRange.next_auto_assign_mac + 1},
        synchronize_session=False)

    # Returns a count of the rows matched in the update
    return query


def mac_range_update_set_full(context, mac_range):
    query = context.session.query(models.MacAddressRange)
    query = query.filter_by(id=mac_range["id"])
    query = query.filter(models.MacAddressRange.next_auto_assign_mac != -1)

    # For details on synchronize_session, see:
    # http://docs.sqlalchemy.org/en/rel_0_8/orm/query.html
    query = query.update(
        {"next_auto_assign_mac": -1},
        synchronize_session=False)

    # Returns a count of the rows matched in the update
    return query


def mac_address_update(context, mac, **kwargs):
    mac.update(kwargs)
    context.session.add(mac)
    return mac


def mac_address_create(context, **mac_dict):
    mac_address = models.MacAddress()
    mac_address.update(mac_dict)
    mac_address["tenant_id"] = context.tenant_id
    mac_address["deallocated"] = False
    mac_address["deallocated_at"] = None
    context.session.add(mac_address)
    return mac_address


INVERT_DEFAULTS = 'invert_defaults'


@scoped
def network_find(context, limit=None, sorts=None, marker=None,
                 page_reverse=False, fields=None, **filters):
    ids = []
    defaults = []
    provider_query = False
    if "id" in filters:
        ids, defaults = STRATEGY.split_network_ids(filters["id"])
        if not ids and defaults and "shared" not in filters:
            provider_query = True
        if ids:
            filters["id"] = ids
        else:
            filters.pop("id")

    if "shared" in filters:
        defaults = STRATEGY.get_provider_networks()
        if True in filters["shared"]:
            if ids:
                defaults = [net for net in ids if net in defaults]
                filters.pop("id")
            if not defaults:
                return []
        else:
            defaults.insert(0, INVERT_DEFAULTS)
        filters.pop("shared")
    return _network_find(context, limit, sorts, marker, page_reverse, fields,
                         defaults=defaults, provider_query=provider_query,
                         **filters)


def _network_find(context, limit, sorts, marker, page_reverse, fields,
                  defaults=None, provider_query=False, **filters):
    query = context.session.query(models.Network)
    model_filters = _model_query(context, models.Network, filters, query)

    if defaults:
        invert_defaults = False
        if INVERT_DEFAULTS in defaults:
            invert_defaults = True
            defaults.pop(0)
        if filters and invert_defaults:
            query = query.filter(and_(not_(models.Network.id.in_(defaults)),
                                      and_(*model_filters)))
        elif not provider_query and filters and not invert_defaults:
            query = query.filter(or_(models.Network.id.in_(defaults),
                                     and_(*model_filters)))

        elif not invert_defaults:
            query = query.filter(models.Network.id.in_(defaults))
    else:
        query = query.filter(*model_filters)

    if "join_subnets" in filters:
        query = query.options(orm.joinedload(models.Network.subnets))

    return paginate_query(query, models.Network, limit, sorts, marker)


def network_create(context, **network):
    new_net = models.Network()
    new_net.update(network)
    context.session.add(new_net)
    return new_net


def network_update(context, network, **kwargs):
    network.update(kwargs)
    context.session.add(network)
    return network


def network_count_all(context):
    query = context.session.query(sql_func.count(models.Network.id))
    return query.filter(
        models.Network.tenant_id == context.tenant_id).scalar()


def network_delete(context, network):
    context.session.delete(network)


def _subnet_find_ordered_by_used_ips(context, net_id, lock_subnets=True,
                                     order="asc", unused=False, **filters):
    count = sql_func.count(models.IPAddress.address).label("count")
    size = (models.Subnet.last_ip - models.Subnet.first_ip)
    query = context.session.query(models.Subnet, count)
    if lock_subnets:
        query = query.with_lockmode("update")
    query = query.filter_by(do_not_use=False)
    query = query.outerjoin(models.Subnet.generated_ips)
    query = query.group_by(models.Subnet.id)

    query = query.order_by(asc(models.Subnet.ip_version))

    if unused:  # find unused subnets
        query = query.having(count == 0)
    else:  # otherwise, order used subnets
        if order == "desc":
            query = query.order_by(desc(size - count))
        else:  # default acending
            query = query.order_by(asc(size - count))

    query = query.filter(models.Subnet.network_id == net_id)
    if "ip_version" in filters:
        query = query.filter(models.Subnet.ip_version == filters["ip_version"])
    if "segment_id" in filters and filters["segment_id"]:
        query = query.filter(models.Subnet.segment_id == filters["segment_id"])
    query = query.filter(models.Subnet.next_auto_assign_ip != -1)

    if "subnet_id" in filters and filters["subnet_id"]:
        query = query.filter(models.Subnet.id.in_(filters["subnet_id"]))
    return query


def subnet_find_ordered_by_most_full(context, net_id, lock_subnets=True,
                                     **filters):
    return _subnet_find_ordered_by_used_ips(
        context, net_id, lock_subnets=lock_subnets, order="asc", **filters)


def subnet_find_ordered_by_least_full(context, net_id, lock_subnets=True,
                                      **filters):
    return _subnet_find_ordered_by_used_ips(
        context, net_id, lock_subnets=lock_subnets, order="desc", **filters)


def subnet_find_unused(context, net_id, lock_subnets=True,
                       **filters):
    return _subnet_find_ordered_by_used_ips(
        context, net_id, lock_subnets=lock_subnets, unused=True, **filters)


def subnet_update_next_auto_assign_ip(context, subnet):
    query = context.session.query(models.Subnet)
    query = query.filter(models.Subnet.id == subnet["id"])
    query = query.filter(models.Subnet.next_auto_assign_ip != -1)

    # For details on synchronize_session, see:
    # http://docs.sqlalchemy.org/en/rel_0_8/orm/query.html
    query = query.update(
        {"next_auto_assign_ip":
         models.Subnet.next_auto_assign_ip + 1},
        synchronize_session=False)

    # Returns a count of the rows matched in the update
    return query


def subnet_update_set_full(context, subnet):
    query = context.session.query(models.Subnet)
    query = query.filter_by(id=subnet["id"])
    query = query.filter(models.Subnet.next_auto_assign_ip != -1)

    # For details on synchronize_session, see:
    # http://docs.sqlalchemy.org/en/rel_0_8/orm/query.html
    query = query.update(
        {"next_auto_assign_ip": -1},
        synchronize_session=False)

    # Returns a count of the rows matched in the update
    return query


def subnet_update_set_alloc_pool_cache(context, subnet, cache_data=None):
    if cache_data is not None:
        cache_data = json.dumps(cache_data)
    update_kwargs = {"_allocation_pool_cache": cache_data}
    query = context.session.query(models.Subnet)
    query = query.filter(models.Subnet.id == subnet.id)
    row_count = query.update(update_kwargs,
                             update_args={"mysql_limit": 1})
    LOG.debug("Setting alloc pool cache to %s (row_count: %s)" % (
        cache_data, row_count))
    return subnet


@scoped
def subnet_find(context, limit=None, page_reverse=False, sorts=None,
                marker_obj=None, fields=None, **filters):
    ids = []
    defaults = []
    provider_query = False
    if "id" in filters:
        ids, defaults = STRATEGY.split_subnet_ids(filters["id"])
        if not ids and defaults and "shared" not in filters:
            provider_query = True
        if ids:
            filters["id"] = ids
        else:
            filters.pop("id")

    if "shared" in filters:
        defaults = STRATEGY.get_provider_subnets()
        if True in filters["shared"]:
            if ids:
                defaults = [sub for sub in ids if sub in defaults]
                filters.pop("id")
            if not defaults:
                return []
        else:
            defaults.insert(0, INVERT_DEFAULTS)
        filters.pop("shared")
    return _subnet_find(context, limit, sorts, marker_obj, page_reverse,
                        fields, defaults=defaults,
                        provider_query=provider_query, **filters)


def _subnet_find(context, limit, sorts, marker, page_reverse, fields,
                 defaults=None, provider_query=False, **filters):
    query = context.session.query(models.Subnet)
    model_filters = _model_query(context, models.Subnet, filters, query)

    if defaults:
        invert_defaults = False
        if INVERT_DEFAULTS in defaults:
            invert_defaults = True
            defaults.pop(0)
        if filters and invert_defaults:
            query = query.filter(and_(not_(models.Subnet.id.in_(defaults)),
                                      and_(*model_filters)))
        elif not provider_query and filters and not invert_defaults:
            query = query.filter(or_(models.Subnet.id.in_(defaults),
                                     and_(*model_filters)))

        elif not invert_defaults:
            query = query.filter(models.Subnet.id.in_(defaults))
    else:
        query = query.filter(*model_filters)

    if "join_dns" in filters:
        query = query.options(orm.joinedload(models.Subnet.dns_nameservers))

    if "join_routes" in filters:
        query = query.options(orm.joinedload(models.Subnet.routes))

    if "join_pool" in filters:
        query = query.options(orm.undefer('_allocation_pool_cache'))

    return paginate_query(query, models.Subnet, limit, sorts, marker)


def subnet_count_all(context, **filters):
    query = context.session.query(sql_func.count(models.Subnet.id))
    if filters.get("network_id"):
        query = query.filter(
            models.Subnet.network_id == filters["network_id"])
    query.filter(models.Subnet.tenant_id == context.tenant_id)
    return query.scalar()


def subnet_delete(context, subnet):
    context.session.delete(subnet)


def subnet_create(context, **subnet_dict):
    subnet = models.Subnet()
    subnet.update(subnet_dict)
    subnet["tenant_id"] = context.tenant_id
    context.session.add(subnet)
    return subnet


def subnet_update(context, subnet, **kwargs):
    subnet.update(kwargs)
    context.session.add(subnet)
    return subnet


@scoped
def route_find(context, fields=None, **filters):
    query = context.session.query(models.Route)
    model_filters = _model_query(context, models.Route, filters)
    return query.filter(*model_filters)


def route_create(context, **route_dict):
    new_route = models.Route()
    new_route.update(route_dict)
    new_route["tenant_id"] = context.tenant_id
    context.session.add(new_route)
    return new_route


def route_update(context, route, **kwargs):
    route.update(kwargs)
    context.session.add(route)
    return route


def route_delete(context, route):
    context.session.delete(route)


def dns_create(context, **dns_dict):
    dns_nameserver = models.DNSNameserver()
    ip = dns_dict.pop("ip")
    dns_nameserver.update(dns_dict)
    dns_nameserver["ip"] = int(ip)
    dns_nameserver["tenant_id"] = context.tenant_id
    context.session.add(dns_nameserver)
    return dns_nameserver


def dns_delete(context, dns):
    context.session.delete(dns)


@scoped
def security_group_find(context, **filters):
    query = context.session.query(models.SecurityGroup).options(
        orm.joinedload(models.SecurityGroup.rules))
    model_filters = _model_query(context, models.SecurityGroup, filters)
    return query.filter(*model_filters)


@scoped
def security_group_count(context, **filters):
    query = context.session.query(sql_func.count(models.SecurityGroup.id))
    model_filters = _model_query(context, models.SecurityGroup, filters)
    return query.filter(*model_filters).scalar()


@scoped
def ports_with_security_groups_find(context):
    query = context.session.query(models.Port)
    query = query.join(models.Port.security_groups)
    query = query.options(orm.contains_eager(models.Port.security_groups))
    return query


@scoped
def ports_with_security_groups_count(context):
    query = context.session.query(
        sql_func.count(models.port_group_association_table.c.port_id))
    return query.scalar()


def security_group_create(context, **sec_group_dict):
    new_group = models.SecurityGroup()
    new_group.update(sec_group_dict)
    new_group["tenant_id"] = context.tenant_id
    context.session.add(new_group)
    return new_group


def security_group_update(context, group, **kwargs):
    group.update(kwargs)
    context.session.add(group)
    return group


def security_group_delete(context, group):
    context.session.delete(group)


@scoped
def security_group_rule_find(context, **filters):
    query = context.session.query(models.SecurityGroupRule)
    model_filters = _model_query(context, models.SecurityGroupRule, filters)
    return query.filter(*model_filters)


def security_group_rule_create(context, **rule_dict):
    new_rule = models.SecurityGroupRule()
    new_rule.update(rule_dict)
    new_rule.group_id = rule_dict['security_group_id']
    new_rule.tenant_id = rule_dict['tenant_id']
    context.session.add(new_rule)
    return new_rule


def security_group_rule_delete(context, rule):
    context.session.delete(rule)


def ip_policy_create(context, **ip_policy_dict):
    new_policy = models.IPPolicy()
    exclude = ip_policy_dict.pop("exclude")
    ip_set = netaddr.IPSet()
    for excluded_cidr in exclude:
        cidr_net = netaddr.IPNetwork(excluded_cidr).ipv6()
        new_policy["exclude"].append(
            models.IPPolicyCIDR(cidr=excluded_cidr,
                                first_ip=cidr_net.first,
                                last_ip=cidr_net.last))
        ip_set.add(excluded_cidr)
    ip_policy_dict["size"] = ip_set.size
    new_policy.update(ip_policy_dict)
    new_policy["tenant_id"] = context.tenant_id
    context.session.add(new_policy)
    return new_policy


@scoped
def ip_policy_find(context, **filters):
    query = context.session.query(models.IPPolicy)
    model_filters = _model_query(context, models.IPPolicy, filters)
    return query.filter(*model_filters)


def ip_policy_update(context, ip_policy, **ip_policy_dict):
    exclude = ip_policy_dict.pop("exclude", [])
    if exclude:
        ip_policy["exclude"] = []
        ip_set = netaddr.IPSet()
        for excluded_cidr in exclude:
            cidr_net = netaddr.IPNetwork(excluded_cidr).ipv6()
            ip_policy["exclude"].append(
                models.IPPolicyCIDR(cidr=excluded_cidr,
                                    first_ip=cidr_net.first,
                                    last_ip=cidr_net.last))
            ip_set.add(excluded_cidr)
        ip_policy_dict["size"] = ip_set.size

    ip_policy.update(ip_policy_dict)
    context.session.add(ip_policy)
    return ip_policy


def ip_policy_delete(context, ip_policy):
    context.session.delete(ip_policy)


def transaction_create(context):
    transaction = models.Transaction()
    context.session.add(transaction)
    return transaction


@scoped
def floating_ip_find(context, lock_mode=False, limit=None, sorts=None,
                     marker=None, page_reverse=False, fields=None, **filters):
    query = context.session.query(models.IPAddress)

    if lock_mode:
        query = query.with_lockmode("update")

    model_filters = _model_query(context, models.IPAddress, filters)

    if filters.get("port_id"):
        model_filters.append(models.IPAddress.ports.any(
            models.Port.id == filters['port_id']))

    if filters.get("transaction_id"):
        model_filters.append(
            models.IPAddress.transaction_id == filters['transaction_id'])

    return paginate_query(query.filter(*model_filters), models.IPAddress,
                          limit, sorts, marker)


def floating_ip_associate_fixed_ip(context, floating_ip, fixed_ip):
    floating_ip.fixed_ips.append(fixed_ip)
    return floating_ip


def floating_ip_disassociate_fixed_ip(context, floating_ip, fixed_ip):
    found_index = None
    for index, flip_fixed_ip in enumerate(floating_ip.fixed_ips):
        if flip_fixed_ip.id == fixed_ip.id:
            found_index = index
            break
    floating_ip.fixed_ips.pop(found_index)
    return floating_ip


def floating_ip_disassociate_all_fixed_ips(context, floating_ip):
    floating_ip.fixed_ips = []
    return floating_ip


@scoped
def lock_holder_find(context, **filters):
    query = context.session.query(models.LockHolder)
    model_filters = _model_query(context, models.LockHolder, filters)
    return query.filter(*model_filters)


def _lock_create(context, target, **kwargs):
    with context.session.begin():
        result = context.session.execute(
            models.Lock.__table__.insert(),
            {"type": kwargs["type"]})
        lock_id = result.lastrowid

        target_model = target.__class__
        row_count = context.session.query(target_model).filter(
            and_(target_model.id == target.id, target_model.lock_id.is_(None))
        ).update(dict(lock_id=lock_id))

    if row_count == 0:
        context.session.query(models.Lock).filter(
            models.Lock.id == lock_id).delete()
        return None
    return lock_id


def lock_holder_create(context, target, **kwargs):
    lock_id = target.lock_id
    if not lock_id:
        lock_id = _lock_create(context, target, **kwargs)
        if not lock_id:
            # Failed to concurrently create lock; invoker must retry
            return
    lock_holder = models.LockHolder(lock_id=lock_id,
                                    name=kwargs["name"])
    context.session.add(lock_holder)
    return lock_holder


def _lock_delete(context, target):
    with context.session.begin():
        lock_id = target.lock_id
        lock_holder = lock_holder_find(context, lock_id=lock_id, scope=ONE)
        if not lock_holder:
            target.lock_id = None
            context.session.add(target)
            context.session.query(
                models.Lock).filter(
                    models.Lock.id == lock_id).delete()


def lock_holder_delete(context, target, lock_holder):
    context.session.delete(lock_holder)
    _lock_delete(context, target)


@scoped
def segment_allocation_range_find(context, lock_mode=False, **filters):
    query = context.session.query(models.SegmentAllocationRange)
    if lock_mode:
        query = query.with_lockmode("update")

    model_filters = _model_query(
        context, models.SegmentAllocationRange, filters)

    query = query.filter(*model_filters)
    return query


def segment_allocation_find(context, lock_mode=False, **filters):
    """Query for segment allocations."""
    range_ids = filters.pop("segment_allocation_range_ids", None)

    query = context.session.query(models.SegmentAllocation)
    if lock_mode:
        query = query.with_lockmode("update")

    query = query.filter_by(**filters)

    # Optionally filter by given list of range ids
    if range_ids:
        query.filter(
            models.SegmentAllocation.segment_allocation_range_id.in_(
                range_ids))
    return query


def segment_allocation_update(context, sa, **sa_dict):
    sa.update(sa_dict)
    context.session.add(sa)
    return sa


def segment_allocation_range_populate_bulk(context, sa_dicts):
    """Bulk-insert deallocated segment allocations.

    NOTE(morgabra): This is quite performant when populating large ranges,
    but you don't get any ORM conveniences or protections here.
    """
    context.session.bulk_insert_mappings(
        models.SegmentAllocation,
        sa_dicts
    )


def segment_allocation_range_create(context, **sa_range_dict):
    new_range = models.SegmentAllocationRange()
    new_range.update(sa_range_dict)
    context.session.add(new_range)
    return new_range


def segment_allocation_range_delete(context, sa_range):
    context.session.delete(sa_range)


@scoped
def async_transaction_find(context, lock_mode=False, **filters):
    query = context.session.query(models.AsyncTransactions)
    if lock_mode:
        query = query.with_lockmode("update")

    model_filters = _model_query(
        context, models.AsyncTransactions, filters)

    query = query.filter(*model_filters)
    return query


def async_transaction_create(context, **transaction_dict):
    tx = models.AsyncTransactions()
    tx.update(transaction_dict)
    context.session.add(tx)
    return tx


def async_transaction_update(context, transaction, **kwargs):
    transaction.update(kwargs)
    context.session.add(transaction)
    return transaction


def async_transaction_delete(context, transaction):
    context.session.delete(transaction)
