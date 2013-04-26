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
from sqlalchemy import orm

from quark.db import models


LOG = logging.getLogger("quantum.quark.db.api")

ONE = "one"
ALL = "all"


def _model_query(context, model, filters, query, fields=None):
    filters = filters or {}
    for key in ["name", "network_id", "id", "device_id", "tenant_id",
                "mac_address"]:
        if key in filters:
            if not filters[key]:
                continue
            listified = filters[key]
            if not isinstance(listified, list):
                listified = [listified]
            filters[key] = listified

    if filters.get("name"):
        query = query.filter(model.name.in_(filters["name"]))

    if filters.get("network_id"):
        query = query.filter(model.network_id.in_(filters["network_id"]))

    if filters.get("mac_address"):
        query = query.filter(model.mac_address.in_(filters["mac_address"]))

    if filters.get("tenant_id"):
        query = query.filter(model.tenant_id.in_(filters["tenant_id"]))

    if filters.get("id"):
        query = query.filter(model.id.in_(filters["id"]))

    if filters.get("reuse_after"):
        reuse_after = filters["reuse_after"]
        reuse = (timeutils.utcnow() -
                 datetime.timedelta(seconds=reuse_after))
        query = query.filter(model.deallocated_at <= reuse)

    if filters.get("subnet_id"):
        query = query.filter(model.subnet_id ==
                             filters["subnet_id"])

    if filters.get("deallocated"):
        query = query.filter(model.deallocated ==
                             filters["deallocated"])

    if filters.get("order_by"):
        query = query.order_by(filters["order_by"])

    if filters.get("address"):
        query = query.filter(model.address == filters["address"])

    if filters.get("deallocated"):
        query = query.filter_by(deallocated=True)

    if filters.get("version"):
        query = query.filter(model.ip_version == filters["version"])

    if filters.get("ip_address"):
        query = query.filter(model.address == int(filters["ip_address"]))

    if filters.get("mac_address_range_id"):
        query = query.filter(model.mac_address_range_id ==
                             filters["mac_address_range_id"])

    if filters.get("cidr"):
        query = query.filter(model.cidr == filters["cidr"])

    return query


def scoped(f):
    def wrapped(*args, **kwargs):
        scope = None
        if "scope" in kwargs:
            scope = kwargs.pop("scope")
        if scope not in [None, ALL, ONE]:
            raise Exception("Invalid scope")
        res = f(*args, **kwargs)
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
    query = _model_query(context, models.Port, filters, query=query)
    if filters.get("device_id"):
        query = query.filter(models.Port.device_id.in_(filters["device_id"]))
    if filters.get("ip_address_id"):
        query = query.filter(models.Port.ip_addresses.any(
            models.IPAddress.id.in_(filters["ip_address_id"])))
    return query


def port_count_all(context, **filters):
    query = context.session.query(sql_func.count(models.Port.id))
    query = _model_query(context, models.Port, filters, query=query)
    return query.scalar()


def port_create(context, **port_dict):
    port = models.Port()
    port.update(port_dict)
    port["tenant_id"] = context.tenant_id
    if "addresses" in port_dict:
        port["ip_addresses"].extend(port_dict["addresses"])
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
    query = _model_query(context, models.IPAddress, filters, query)
    if filters.get("device_id"):
        query = query.filter(models.IPAddress.ports.any(
            models.Port.device_id.in_(filters["device_id"])))
    return query


@scoped
def mac_address_find(context, **filters):
    query = context.session.query(models.MacAddress)
    query = _model_query(context, models.MacAddress, filters, query)
    return query


def mac_address_range_find_allocation_counts(context):
    query = context.session.query(models.MacAddressRange,
                                  sql_func.count(models.MacAddress.address).
                                  label("count")).\
        outerjoin(models.MacAddress).\
        group_by(models.MacAddressRange).\
        order_by("count DESC")
    return query


@scoped
def mac_address_range_find(context, **filters):
    query = context.session.query(models.MacAddressRange)
    query = _model_query(context, models.MacAddressRange, filters, query)
    return query


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
    # TODO(mdietz): we don't support "shared" networks yet. The concept
    #               is broken
    if filters.get("shared") and True in filters["shared"]:
        return []
    query = context.session.query(models.Network)
    query = _model_query(context, models.Network, filters, query)
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
    query = context.session.query(models.Subnet).\
        options(orm.joinedload(models.Subnet.routes))
    query = _model_query(context, models.Subnet, filters, query)
    return query


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
    query = _model_query(context, models.Route, filters, query)
    return query


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
