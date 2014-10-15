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

import datetime
import inspect

import netaddr
from neutron.openstack.common import log as logging
from neutron.openstack.common import timeutils
from neutron.openstack.common import uuidutils
from oslo.config import cfg
from sqlalchemy import event, exc
from sqlalchemy import func as sql_func
from sqlalchemy import and_, asc, desc, orm, or_, not_
from sqlalchemy.pool import Pool

from quark.db import models
from quark import network_strategy


STRATEGY = network_strategy.STRATEGY
LOG = logging.getLogger(__name__)
CONF = cfg.CONF

quark_opts = [
    cfg.BoolOpt('pessimistic_connection_pooling',
                default=False,
                help=_('Controls whether or not we pessimistically recreate '
                       'sqlalchemy connections in the pool.'))]

CONF.register_opts(quark_opts, "QUARK")

ONE = "one"
ALL = "all"


# NOTE(jkoelker) init event listener that will ensure id is filled in
#                on object creation (prior to commit).
def _perhaps_generate_id(target, args, kwargs):
    if hasattr(target, 'id') and target.id is None:
        target.id = uuidutils.generate_uuid()


if CONF.QUARK.pessimistic_connection_pooling:
    @event.listens_for(Pool, "checkout")
    def ping_connection(dbapi_connection, connection_record, connection_proxy):
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("SELECT 1")
        except Exception:
            raise exc.DisconnectionError()
        cursor.close()


# NOTE(jkoelker) Register the event on all models that have ids
for _name, klass in inspect.getmembers(models, inspect.isclass):
    if klass is models.HasId:
        continue

    if models.HasId in klass.mro():
        event.listen(klass, "init", _perhaps_generate_id)


def _listify(filters):
    for key in ["name", "network_id", "id", "device_id", "tenant_id",
                "subnet_id", "mac_address", "shared", "version", "segment_id",
                "device_owner", "ip_address", "used_by_tenant_id"]:
        if key in filters:
            if not filters[key]:
                continue
            listified = filters[key]
            if not isinstance(listified, list):
                listified = [listified]
            filters[key] = listified


def _model_query(context, model, filters, fields=None):
    filters = filters or {}
    model_filters = []

    if filters.get("name"):
        model_filters.append(model.name.in_(filters["name"]))

    if filters.get("network_id"):
        model_filters.append(model.network_id.in_(filters["network_id"]))

    if filters.get("mac_address"):
        model_filters.append(model.mac_address.in_(filters["mac_address"]))

    if filters.get("segment_id"):
        model_filters.append(model.segment_id.in_(filters["segment_id"]))

    if filters.get("id"):
        model_filters.append(model.id.in_(filters["id"]))

    if filters.get("reuse_after"):
        reuse_after = filters["reuse_after"]
        reuse = (timeutils.utcnow() -
                 datetime.timedelta(seconds=reuse_after))
        model_filters.append(model.deallocated_at <= reuse)

    if filters.get("subnet_id"):
        model_filters.append(model.subnet_id.in_(filters["subnet_id"]))

    if filters.get("deallocated"):
        model_filters.append(model.deallocated == filters["deallocated"])

    if filters.get("_deallocated") is not None:
        if filters.get("_deallocated"):
            model_filters.append(model._deallocated == 1)
        else:
            model_filters.append(model._deallocated != 1)

    if filters.get("address"):
        model_filters.append(model.address == filters["address"])

    if filters.get("version"):
        model_filters.append(model.version.in_(filters["version"]))

    if filters.get("ip_version"):
        model_filters.append(model.ip_version == filters["ip_version"])

    if filters.get("ip_address"):
        model_filters.append(model.address.in_(
            [ip.ipv6().value for ip in filters["ip_address"]]))

    if filters.get("mac_address_range_id"):
        model_filters.append(model.mac_address_range_id ==
                             filters["mac_address_range_id"])

    if filters.get("cidr"):
        model_filters.append(model.cidr == filters["cidr"])

    # Inject the tenant id if none is set. We don't need unqualified queries.
    # This works even when a non-shared, other-tenant owned network is passed
    # in because the authZ checks that happen in Neutron above us yank it back
    # out of the result set.
    if not filters and not context.is_admin:
        filters["tenant_id"] = [context.tenant_id]
    # Begin:Added for RM6299
    if filters.get("used_by_tenant_id"):
        model_filters.append(model.used_by_tenant_id.in_(
                             filters["used_by_tenant_id"]))
    if filters.get("tenant_id"):
        if model == models.IPAddress:
            model_filters.append(model.used_by_tenant_id.in_(
                                 filters["tenant_id"]))
        else:
            model_filters.append(model.tenant_id.in_(filters["tenant_id"]))
    # End: Added for RM6299
    if filters.get("device_owner"):
        model_filters.append(model.device_owner.in_(filters["device_owner"]))

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
def port_find(context, fields=None, **filters):
    query = context.session.query(models.Port).options(
        orm.joinedload(models.Port.ip_addresses))
    model_filters = _model_query(context, models.Port, filters)
    if filters.get("ip_address_id"):
        model_filters.append(models.Port.ip_addresses.any(
            models.IPAddress.id.in_(filters["ip_address_id"])))

    if filters.get("device_id"):
        model_filters.append(models.Port.device_id.in_(filters["device_id"]))

    if "join_security_groups" in filters:
        query = query.options(orm.joinedload(models.Port.security_groups))

    if fields and "port_subnets" in fields:
        query = query.options(orm.joinedload("ip_addresses.subnet"))
        query = query.options(
            orm.joinedload("ip_addresses.subnet.dns_nameservers"))
        query = query.options(
            orm.joinedload("ip_addresses.subnet.routes"))

    return query.filter(*model_filters).order_by(asc(models.Port.created_at))


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
    port = models.Port()
    port.update(port_dict)
    port["tenant_id"] = context.tenant_id
    if "addresses" in port_dict:
        port["ip_addresses"].extend(port_dict["addresses"])
    context.session.add(port)
    return port


def port_update(context, port, **kwargs):
    if "addresses" in kwargs:
        port["ip_addresses"] = kwargs.pop("addresses")
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


@scoped
def ip_address_find(context, lock_mode=False, **filters):
    query = context.session.query(models.IPAddress)
    query = query.join(models.Subnet)

    if lock_mode:
        query = query.with_lockmode("update")

    ip_shared = filters.pop("shared", None)
    if ip_shared is not None:
        cnt = sql_func.count(models.port_ip_association_table.c.port_id)
        stmt = context.session.query(models.IPAddress,
                                     cnt.label("ports_count"))
        stmt = stmt.outerjoin(models.port_ip_association_table)
        stmt = stmt.group_by(models.IPAddress.id).subquery()

        query = query.outerjoin(stmt, stmt.c.id == models.IPAddress.id)

        # !@# HACK(amir): replace once attributes are configured in ip address
        #                extension correctly
        if "True" in ip_shared:
            query = query.filter(stmt.c.ports_count > 1)
        else:
            query = query.filter(stmt.c.ports_count <= 1)

    model_filters = _model_query(context, models.IPAddress, filters)
    if "do_not_use" in filters:
        query = query.filter(models.Subnet.do_not_use == filters["do_not_use"])

    if filters.get("device_id"):
        model_filters.append(models.IPAddress.ports.any(
            models.Port.device_id.in_(filters["device_id"])))
    return query.filter(*model_filters)


@scoped
def mac_address_find(context, lock_mode=False, **filters):
    query = context.session.query(models.MacAddress)
    if lock_mode:
        query = query.with_lockmode("update")
    model_filters = _model_query(context, models.MacAddress, filters)
    return query.filter(*model_filters)


def mac_address_range_find_allocation_counts(context, address=None):
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


# FIXME(amir): RM9305/RM9709: do not allow a tenant to act on a network that is
#              not shared nor does not belong to them
def _remove_unauthorized_networks(f):
    def wrapped(*args, **kwargs):
        context = args[0]
        tenant_id = context.tenant_id
        net_or_nets = f(*args, **kwargs)

        def _auth_filter(net):
            if not net:
                return False
            if STRATEGY.is_parent_network(net["id"]):
                return True
            if ((tenant_id is None and context.is_admin) or
                    net["tenant_id"] == tenant_id):
                return True
            return False

        try:
            # net_or_nets is list or Query object
            return [net for net in net_or_nets if _auth_filter(net)]
        except TypeError:
            # net_or_nets is a single Network
            if _auth_filter(net_or_nets):
                return net_or_nets
        return None

    return wrapped


@_remove_unauthorized_networks
@scoped
def network_find(context, fields=None, **filters):
    ids = []
    defaults = []
    if "id" in filters:
        ids, defaults = STRATEGY.split_network_ids(context, filters["id"])
        if ids:
            filters["id"] = ids
        else:
            filters.pop("id")

    if "shared" in filters:
        defaults = STRATEGY.get_assignable_networks(context)
        if True in filters["shared"]:
            if ids:
                defaults = [net for net in ids if net in defaults]
                filters.pop("id")
            if not defaults:
                return []
        else:
            defaults.insert(0, INVERT_DEFAULTS)
        filters.pop("shared")
    return _network_find(context, fields, defaults=defaults, **filters)


def _network_find(context, fields, defaults=None, **filters):
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
        elif filters and not invert_defaults:
            query = query.filter(or_(models.Network.id.in_(defaults),
                                     and_(*model_filters)))

        elif not invert_defaults:
            query = query.filter(models.Network.id.in_(defaults))
    else:
        query = query.filter(*model_filters)

    if "join_subnets" in filters:
        query = query.options(orm.joinedload(models.Network.subnets))

    return query


def network_find_all(context, fields=None, **filters):
    return network_find(context, fields, **filters).all()


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


def subnet_find_ordered_by_most_full(context, net_id, **filters):
    count = sql_func.count(models.IPAddress.address).label("count")
    size = (models.Subnet.last_ip - models.Subnet.first_ip)
    remaining = (size + 1 - count)
    query = context.session.query(models.Subnet, count).with_lockmode('update')
    query = query.filter_by(do_not_use=False)
    query = query.outerjoin(models.Subnet.generated_ips)
    query = query.group_by(models.Subnet.id)
    query = query.order_by(desc(remaining))

    query = query.filter(models.Subnet.network_id == net_id)
    if "ip_version" in filters:
        query = query.filter(models.Subnet.ip_version == filters["ip_version"])
    if "segment_id" in filters and filters["segment_id"]:
        query = query.filter(models.Subnet.segment_id == filters["segment_id"])
    if "subnet_id" in filters and filters["subnet_id"]:
        query = query.filter(models.Subnet.id.in_(filters["subnet_id"]))
    query = query.filter(models.Subnet.next_auto_assign_ip != -1)
    return query


@scoped
def subnet_find(context, **filters):
    if "shared" in filters and True in filters["shared"]:
        return []
    query = context.session.query(models.Subnet)
    model_filters = _model_query(context, models.Subnet, filters)

    if "join_dns" in filters:
        query = query.options(orm.joinedload(models.Subnet.dns_nameservers))

    if "join_routes" in filters:
        query = query.options(orm.joinedload(models.Subnet.routes))

    return query.filter(*model_filters)


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
