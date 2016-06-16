# Copyright 2014 Rackspace Hosting Inc.
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

import netaddr
from neutron.extensions import securitygroup as sg_ext
from neutron_lib import exceptions as n_exc
from oslo_config import cfg
from oslo_log import log as logging

from quark import exceptions as q_exc


LOG = logging.getLogger(__name__)
CONF = cfg.CONF

# Neutron doesn't officially support any other ethertype
ETHERTYPES = {
    "IPv4": 0x0800,
    "IPv6": 0x86DD
}

PROTOCOLS_V4 = {"icmp": 1, "tcp": 6, "udp": 17}
PROTOCOLS_V6 = {"tcp": 6, "udp": 17, "icmp": 58}

# Neutron only officially supports TCP, ICMP and UDP,
# with ethertypes IPv4 and IPv6
PROTOCOL_MAP = {
    ETHERTYPES["IPv4"]: PROTOCOLS_V4,
    ETHERTYPES["IPv6"]: PROTOCOLS_V6
}


ALLOWED_PROTOCOLS = None
ALLOWED_WITH_RANGE = [1, 6, 17, 58]
MIN_PROTOCOL = 0
MAX_PROTOCOL = 255
REVERSE_PROTOCOL_MAP = {}
REVERSE_ETHERTYPES = {}
MIN_PORT = 0
MAX_PORT = 65535


def _is_allowed(protocol, ethertype):
    # Please see http://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
    # The field is always 8 bits wide.
    if not (MIN_PROTOCOL <= protocol <= MAX_PROTOCOL):
        return False

    return (protocol in PROTOCOL_MAP[ethertype] or
            protocol in REVERSE_PROTOCOL_MAP)


def translate_ethertype(ethertype):
    if ethertype not in ETHERTYPES:
        raise q_exc.InvalidEthertype(ethertype=ethertype)
    return ETHERTYPES[ethertype]


def translate_protocol(protocol, ethertype):
    ether = translate_ethertype(ethertype)
    try:
        proto = int(protocol)
    except ValueError:
        proto = str(protocol).lower()
        proto = PROTOCOL_MAP[ether].get(proto, -1)

    if not _is_allowed(proto, ether):
        # TODO(mdietz) This will change as neutron supports new protocols
        value_list = PROTOCOL_MAP[ETHERTYPES["IPv4"]].keys()
        raise sg_ext.SecurityGroupRuleInvalidProtocol(
            protocol=protocol, values=value_list)
    return proto


def human_readable_ethertype(ethertype):
    return REVERSE_ETHERTYPES[ethertype]


def human_readable_protocol(protocol, ethertype):
    if protocol is None:
        return
    proto = translate_protocol(protocol, ethertype)
    return REVERSE_PROTOCOL_MAP[proto]


def validate_remote_ip_prefix(ethertype, prefix):
    if prefix:
        net = netaddr.IPNetwork(prefix)
        if ((ethertype == ETHERTYPES["IPv4"] and net.version == 6) or
                (ethertype == ETHERTYPES["IPv6"] and net.version == 4)):
            human_ether = human_readable_ethertype(ethertype)
            raise n_exc.InvalidInput(
                error_message="Etherytype %s does not match "
                              "remote_ip_prefix, which is IP version %s" %
                              (human_ether, net.version))


def validate_protocol_with_port_ranges(ethertype, protocol, port_range_min,
                                       port_range_max):
    if protocol in ALLOWED_WITH_RANGE:
        if protocol == PROTOCOL_MAP[ethertype]["icmp"]:
            if port_range_min is None and port_range_max is not None:
                raise sg_ext.SecurityGroupMissingIcmpType(value=port_range_max)
            elif port_range_min is not None:
                attr = None
                field = None
                value = None
                if port_range_min < 0 or port_range_min > 255:
                    field = "port_range_min"
                    attr = "type"
                    value = port_range_min
                elif (port_range_max is not None and
                      port_range_max < 0 or port_range_max > 255):
                    field = "port_range_max"
                    attr = "code"
                    value = port_range_max

                if attr and field and value:
                    raise sg_ext.SecurityGroupInvalidIcmpValue(
                        field=field, attr=attr, value=value)

        else:
            if (port_range_min is None) != (port_range_max is None):
                # TODO(anyone): what exactly is a TCP or UDP rule withouts
                #               ports?
                raise n_exc.InvalidInput(
                    error_message="For TCP/UDP rules, port_range_min and"
                                  "port_range_max must either both be supplied"
                                  ", or neither of them")

            if port_range_min is not None and port_range_max is not None:
                if port_range_min > port_range_max:
                    raise sg_ext.SecurityGroupInvalidPortRange()

                if port_range_min < MIN_PORT or port_range_max > MAX_PORT:
                    raise n_exc.InvalidInput(
                        error_message="port_range_min and port_range_max must "
                                      "be >= %s and <= %s" % (MIN_PORT,
                                                              MAX_PORT))


def _init_protocols():
    if not REVERSE_PROTOCOL_MAP:
        for ether_str, ethertype in ETHERTYPES.iteritems():
            for proto, proto_int in PROTOCOL_MAP[ethertype].iteritems():
                REVERSE_PROTOCOL_MAP[proto_int] = proto.upper()

    if not REVERSE_ETHERTYPES:
        for ether_str, ethertype in ETHERTYPES.iteritems():
            REVERSE_ETHERTYPES[ethertype] = ether_str


_init_protocols()
