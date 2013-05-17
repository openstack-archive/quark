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

from quantum.openstack.common import log as logging
from quantum.openstack.common import timeutils
from sqlalchemy import func as sql_func
from sqlalchemy import orm, or_

from quark.db import models
from quark import exceptions as quark_exc
from quark import network_strategy


STRATEGY = network_strategy.STRATEGY
LOG = logging.getLogger("quantum.quark.db.api")

ONE = "one"
ALL = "all"


def _listify(filters):
    for key in ["name", "network_id", "id", "device_id", "tenant_id",
                "mac_address", "shared"]:
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

    if "shared" in filters and True in filters["shared"]:
        return model_filters

    # Inject the tenant id if none is set. We don't need unqualified queries
    if not (context.is_admin or "tenant_id" in filters):
        filters["tenant_id"] = [context.tenant_id]

    if filters.get("name"):
        model_filters.append(model.name.in_(filters["name"]))

    if filters.get("network_id"):
        model_filters.append(model.network_id.in_(filters["network_id"]))

    if filters.get("mac_address"):
        model_filters.append(model.mac_address.in_(filters["mac_address"]))

    if filters.get("tenant_id"):
        model_filters.append(model.tenant_id.in_(filters["tenant_id"]))

    if filters.get("id"):
        model_filters.append(model.id.in_(filters["id"]))

    if filters.get("reuse_after"):
        reuse_after = filters["reuse_after"]
        reuse = (timeutils.utcnow() -
                 datetime.timedelta(seconds=reuse_after))
        model_filters.append(model.deallocated_at <= reuse)

    if filters.get("subnet_id"):
        model_filters.append(model.subnet_id ==
                             filters["subnet_id"])

    if filters.get("deallocated"):
        model_filters.append(model.deallocated ==
                             filters["deallocated"])

    if filters.get("device_id"):
        model_filters.append(models.Port.device_id.in_(filters["device_id"]))

    if filters.get("address"):
        model_filters.append(model.address == filters["address"])

    if filters.get("version"):
        model_filters.append(model.ip_version == filters["version"])

    if filters.get("ip_address"):
        model_filters.append(model.address == int(filters["ip_address"]))

    if filters.get("mac_address_range_id"):
        model_filters.append(model.mac_address_range_id ==
                             filters["mac_address_range_id"])

    if filters.get("cidr"):
        model_filters.append(model.cidr == filters["cidr"])

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
            return res.all()
        elif scope == ONE:
            return res.first()
        return res
    return wrapped


@scoped
def port_find(context, **filters):
    query = context.session.query(models.Port).\
        options(orm.joinedload(models.Port.ip_addresses))
    model_filters = _model_query(context, models.Port, filters)

    if filters.get("ip_address_id"):
        model_filters.append(models.Port.ip_addresses.any(
            models.IPAddress.id.in_(filters["ip_address_id"])))

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
    ip_address["address"] = int(address)
    ip_address["address_readable"] = str(address)
    ip_address["tenant_id"] = context.tenant_id
    ip_address["_deallocated"] = 0
    context.session.add(ip_address)
    return ip_address


@scoped
def ip_address_find(context, **filters):
    query = context.session.query(models.IPAddress)
    model_filters = _model_query(context, models.IPAddress, filters)
    if filters.get("device_id"):
        model_filters.append(models.IPAddress.ports.any(
            models.Port.device_id.in_(filters["device_id"])))
    return query.filter(*model_filters)


@scoped
def mac_address_find(context, **filters):
    query = context.session.query(models.MacAddress)
    model_filters = _model_query(context, models.MacAddress, filters)
    return query.filter(*model_filters)


def mac_address_range_find_allocation_counts(context, address=None):
    query = context.session.query(models.MacAddressRange,
                                  sql_func.count(models.MacAddress.address).
                                  label("count"))
    query = query.outerjoin(models.MacAddress)
    query = query.group_by(models.MacAddressRange)
    query = query.order_by("count DESC")
    if address:
        query = query.filter(models.MacAddressRange.last_address >= address)
        query = query.filter(models.MacAddressRange.first_address <= address)
    return query


@scoped
def mac_address_range_find(context, **filters):
    query = context.session.query(models.MacAddressRange)
    model_filters = _model_query(context, models.MacAddressRange, filters)
    return query.filter(*model_filters)


def mac_address_range_create(context, **range_dict):
    new_range = models.MacAddressRange()
    new_range.update(range_dict)
    new_range["tenant_id"] = context.tenant_id
    context.session.add(new_range)
    return new_range


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


@scoped
def network_find(context, fields=None, **filters):
    ids = []
    defaults = []
    if "id" in filters:
        ids, defaults = STRATEGY.split_network_ids(context, filters["id"])
        filters["ids"] = ids

    if "shared" in filters and True in filters["shared"]:
        defaults = STRATEGY.get_assignable_networks(context)
        if ids:
            defaults = [net for net in ids if net in defaults]
            filters.pop("id")
        if not defaults:
            return []

        if "segment_id" in filters and filters["segment_id"]:
            # Ambiguous search, say we can't find anything
            if len(defaults) > 1:
                raise quark_exc.AmbiguousNetworkId()
            defaults = [STRATEGY.best_match_network_id(
                context, filters["id"][0], filters["segment_id"])]

    query = context.session.query(models.Network)
    model_filters = _model_query(context, models.Network, filters, query)

    if defaults:
        query = query.filter(or_(models.Network.id.in_(defaults),
                             *model_filters))
    else:
        query = query.filter(*model_filters)
    return query


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
    return query.filter(models.Network.tenant_id == context.tenant_id).\
        scalar()


def network_delete(context, network):
    context.session.delete(network)


def subnet_find_allocation_counts(context, net_id, **filters):
    query = context.session.query(models.Subnet,
                                  sql_func.count(models.IPAddress.subnet_id).
                                  label('count')).\
        outerjoin(models.Subnet.allocated_ips).\
        filter(models.Subnet.network_id == net_id)
    if "version" in filters:
        query = query.filter(models.Subnet.ip_version == filters["version"])
    query = query.group_by(models.IPAddress)
    query = query.order_by("count DESC")
    return query


@scoped
def subnet_find(context, **filters):
    if "shared" in filters and True in filters["shared"]:
        return []
    query = context.session.query(models.Subnet).\
        options(orm.joinedload(models.Subnet.routes))
    model_filters = _model_query(context, models.Subnet, filters)
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
    query = context.session.query(models.SecurityGroup)
    model_filters = _model_query(context, models.SecurityGroup, filters)
    return query.filter(*model_filters)


def security_group_create(context, **sec_group_dict):
    new_group = models.SecurityGroup()
    new_group.update(sec_group_dict)
    new_group["tenant_id"] = context.tenant_id
    context.session.add(new_group)
    return new_group


def security_group_update(context, group, **kwargs):
    group.update(kwargs["security_group"])
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
    context.session.add(new_rule)
    return new_rule


def security_group_rule_update(context, rule, **kwargs):
    rule.update(kwargs)
    context.session.add(rule)
    return rule


def security_group_rule_delete(context, rule):
    context.session.delete(rule)
