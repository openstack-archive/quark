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

"""
View Helpers for Quark Plugin
"""

import netaddr
from neutron.openstack.common import log as logging
from oslo.config import cfg

from quark.db import models
from quark import network_strategy
from quark import protocols


CONF = cfg.CONF
LOG = logging.getLogger(__name__)
STRATEGY = network_strategy.STRATEGY

quark_view_opts = [
    cfg.BoolOpt('show_allocation_pools',
                default=True,
                help=_('Controls whether or not to calculate and display'
                       'allocation pools or not')),
    cfg.BoolOpt('show_ipam_strategy',
                default=False,
                help=_('Controls whether or not to show ipam_strategy')),
    cfg.BoolOpt('show_subnet_ip_policy_id',
                default=True,
                help=_('Controls whether or not to show ip_policy_id for'
                       'subnets'))
]

CONF.register_opts(quark_view_opts, "QUARK")


def _is_default_route(route):
    return route.value == 0


def _make_network_dict(network, fields=None):
    shared_net = STRATEGY.is_parent_network(network["id"])
    res = {"id": network["id"],
           "name": network.get("name"),
           "tenant_id": network.get("tenant_id"),
           "admin_state_up": None,
           "status": "ACTIVE",
           "shared": shared_net}
    if CONF.QUARK.show_ipam_strategy:
        res['ipam_strategy'] = network.get("ipam_strategy")

    if not shared_net:
        if fields and "all_subnets" in fields:
            res["subnets"] = [_make_subnet_dict(s)
                              for s in network.get("subnets", [])]
        else:
            res["subnets"] = [s["id"] for s in network.get("subnets", [])]
    else:
        res["subnets"] = []
    return res


def _pools_from_cidr(cidr):
    cidrs = cidr.iter_cidrs()
    if len(cidrs) == 0:
        return []
    if len(cidrs) == 1:
        return [dict(start=str(cidrs[0][0]),
                     end=str(cidrs[0][-1]))]

    pool_start = cidrs[0][0]
    prev_cidr_end = cidrs[0][-1]
    pools = []
    for cidr in cidrs[1:]:
        cidr_start = cidr[0]
        if prev_cidr_end + 1 != cidr_start:
            pools.append(dict(start=str(pool_start),
                              end=str(prev_cidr_end)))
            pool_start = cidr_start
        prev_cidr_end = cidr[-1]
    pools.append(dict(start=str(pool_start), end=str(prev_cidr_end)))
    return pools


def _make_subnet_dict(subnet, fields=None):
    dns_nameservers = [str(netaddr.IPAddress(dns["ip"]))
                       for dns in subnet.get("dns_nameservers")]
    net_id = STRATEGY.get_parent_network(subnet["network_id"])

    def _allocation_pools(subnet):
        ip_policy_cidrs = models.IPPolicy.get_ip_policy_cidrs(subnet)
        cidr = netaddr.IPSet([netaddr.IPNetwork(subnet["cidr"])])
        allocatable = cidr - ip_policy_cidrs
        return _pools_from_cidr(allocatable)

    res = {"id": subnet.get("id"),
           "name": subnet.get("name"),
           "tenant_id": subnet.get("tenant_id"),
           "network_id": net_id,
           "ip_version": subnet.get("ip_version"),
           "dns_nameservers": dns_nameservers or [],
           "cidr": subnet.get("cidr"),
           "shared": STRATEGY.is_parent_network(net_id),
           "enable_dhcp": None}

    if CONF.QUARK.show_subnet_ip_policy_id:
        res['ip_policy_id'] = subnet.get("ip_policy_id")

    if CONF.QUARK.show_allocation_pools:
        res["allocation_pools"] = _allocation_pools(subnet)
    else:
        res["allocation_pools"] = []

    def _host_route(route):
        return {"destination": route["cidr"],
                "nexthop": route["gateway"]}

    # TODO(mdietz): really inefficient, should go away
    res["gateway_ip"] = None
    res["host_routes"] = []
    default_found = False
    for route in subnet["routes"]:
        netroute = netaddr.IPNetwork(route["cidr"])
        if _is_default_route(netroute):
            # NOTE(mdietz): This has the potential to find more than one
            #       default route. Quark normally won't allow you to create
            #       more than one, but it's plausible one exists regardless.
            #       As such, we're going to pretend it isn't possible, but
            #       log it anyway.
            if default_found:
                LOG.info(_("Default route %(gateway_ip)s already found for "
                           "subnet %(id)s") % res)
            res["gateway_ip"] = route["gateway"]
            default_found = True
        else:
            res["host_routes"].append(_host_route(route))
    return res


def _make_security_group_dict(security_group, fields=None):
    res = {"id": security_group.get("id"),
           "description": security_group.get("description"),
           "name": security_group.get("name"),
           "tenant_id": security_group.get("tenant_id")}
    res["security_group_rules"] = [
        r.id for r in security_group["rules"]]
    return res


def _make_security_group_rule_dict(security_rule, fields=None):
    ethertype = protocols.human_readable_ethertype(
        security_rule.get("ethertype"))
    protocol = protocols.human_readable_protocol(
        security_rule.get("protocol"), ethertype)

    res = {"id": security_rule.get("id"),
           "ethertype": ethertype,
           "direction": security_rule.get("direction"),
           "tenant_id": security_rule.get("tenant_id"),
           "port_range_max": security_rule.get("port_range_max"),
           "port_range_min": security_rule.get("port_range_min"),
           "protocol": protocol,
           "remote_ip_prefix": security_rule.get("remote_ip_prefix"),
           "security_group_id": security_rule.get("group_id"),
           "remote_group_id": security_rule.get("remote_group_id")}
    return res


def _port_dict(port, fields=None):
    res = {"id": port.get("id"),
           "name": port.get("name"),
           "network_id": STRATEGY.get_parent_network(port["network_id"]),
           "tenant_id": port.get("tenant_id"),
           "mac_address": port.get("mac_address"),
           "admin_state_up": port.get("admin_state_up"),
           "status": "ACTIVE",
           "security_groups": [group.get("id", None) for group in
                               port.get("security_groups", None)],
           "device_id": port.get("device_id"),
           "device_owner": port.get("device_owner")}

    if "mac_address" in res and res["mac_address"]:
        mac = str(netaddr.EUI(res["mac_address"])).replace('-', ':')
        res["mac_address"] = mac

    # NOTE(mdietz): more pythonic key in dict check fails here. Leave as get
    if port.get("bridge"):
        res["bridge"] = port["bridge"]
    return res


def _make_port_address_dict(ip, fields=None):
    ip_addr = {"subnet_id": ip.get("subnet_id"),
               "ip_address": ip.formatted()}
    if fields and "port_subnets" in fields:
        ip_addr["subnet"] = _make_subnet_dict(ip["subnet"])

    return ip_addr


def _make_port_dict(port, fields=None):
    res = _port_dict(port)
    res["fixed_ips"] = [_make_port_address_dict(ip, fields)
                        for ip in port.ip_addresses]
    return res


def _make_ports_list(query, fields=None):
    ports = []
    for port in query:
        port_dict = _port_dict(port, fields)
        port_dict["fixed_ips"] = [_make_port_address_dict(addr, fields)
                                  for addr in port.ip_addresses]
        ports.append(port_dict)
    return ports


def _make_subnets_list(query, fields=None):
    subnets = []
    for subnet in query:
        subnet_dict = _make_subnet_dict(subnet, fields=fields)
        subnets.append(subnet_dict)
    return subnets


def _make_mac_range_dict(mac_range):
    return {"id": mac_range["id"],
            "cidr": mac_range["cidr"]}


def _make_route_dict(route):
    return {"id": route["id"],
            "cidr": route["cidr"],
            "gateway": route["gateway"],
            "subnet_id": route["subnet_id"]}


def _make_ip_dict(address):
    net_id = STRATEGY.get_parent_network(address["network_id"])
    return {"id": address["id"],
            "network_id": net_id,
            "address": address.formatted(),
            "port_ids": [port["id"] for port in address["ports"]],
            "device_ids": [port["device_id"] or ""
                           for port in address["ports"]],
            "subnet_id": address["subnet_id"],
            "used_by_tenant_id": address["used_by_tenant_id"],
            "version": address["version"],
            "shared": len(address["ports"]) > 1}


def _make_ip_policy_dict(ipp):
    return {"id": ipp["id"],
            "tenant_id": ipp["tenant_id"],
            "name": ipp["name"],
            "subnet_ids": [s["id"] for s in ipp["subnets"]],
            "network_ids": [n["id"] for n in ipp["networks"]],
            "exclude": [ippc["cidr"] for ippc in ipp["exclude"]]}
