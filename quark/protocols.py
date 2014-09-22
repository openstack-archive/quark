# Copyright 2014 Openstack Foundation
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
from neutron.extensions import securitygroup as sg_ext
from neutron.openstack.common import log as logging
from oslo.config import cfg

from quark import exceptions as q_exc


LOG = logging.getLogger(__name__)
CONF = cfg.CONF

# Neutron doesn't officially support any other ethertype
ETHERTYPES = {
    "IPv4": 0x0800,
    "IPv6": 0x86DD
}

# Neutron only officially supports TCP, ICMP and UDP,
# with ethertypes IPv4 and IPv6
PROTOCOLS = {
    ETHERTYPES["IPv4"]: {
        "icmp": 1,
        "tcp": 6,
        "udp": 17,
    },
    ETHERTYPES["IPv6"]: {
        "icmp": 1,
        "tcp": 6,
        "udp": 17
    }
}


ALLOWED_PROTOCOLS = None
ALLOWED_WITH_RANGE = [6, 17]
MIN_PROTOCOL = 0
MAX_PROTOCOL = 255
REVERSE_PROTOCOLS = {}
REVERSE_ETHERTYPES = {}
MIN_PORT = 0
MAX_PORT = 65535


def _is_allowed(protocol, ethertype):
    # Please see http://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
    # The field is always 8 bits wide.
    if not (MIN_PROTOCOL <= protocol <= MAX_PROTOCOL):
        return False

    return (protocol in PROTOCOLS[ethertype] or
            protocol in REVERSE_PROTOCOLS)


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
        proto = PROTOCOLS[ether].get(proto, -1)

    if not _is_allowed(proto, ether):
        # TODO(mdietz) This will change as neutron supports new protocols
        value_list = PROTOCOLS[ETHERTYPES["IPv4"]].keys()
        raise sg_ext.SecurityGroupRuleInvalidProtocol(
            protocol=protocol, values=value_list)
    return proto


def human_readable_ethertype(ethertype):
    return REVERSE_ETHERTYPES[ethertype]


def human_readable_protocol(protocol, ethertype):
    if protocol is None:
        return
    proto = translate_protocol(protocol, ethertype)
    return REVERSE_PROTOCOLS[proto]


def validate_protocol_with_port_ranges(protocol, port_range_min,
                                       port_range_max):
    if protocol in ALLOWED_WITH_RANGE:
        # TODO(anyone): what exactly is a TCP or UDP rule without ports?
        if (port_range_min is None) != (port_range_max is None):
            raise exceptions.InvalidInput(
                error_message="For TCP/UDP rules, port_range_min and"
                              "port_range_max must either both be supplied, "
                              "or neither of them")

        if port_range_min is not None and port_range_max is not None:
            if port_range_min > port_range_max:
                raise sg_ext.SecurityGroupInvalidPortRange()

            if port_range_min < MIN_PORT or port_range_max > MAX_PORT:
                raise exceptions.InvalidInput(
                    error_message="port_range_min and port_range_max must be "
                                  ">= %s and <= %s" % (MIN_PORT, MAX_PORT))
    else:
        if port_range_min or port_range_max:
            raise exceptions.InvalidInput(
                error_message=("You may not supply ports for the requested "
                               "protocol"))


def _init_protocols():
    if not REVERSE_PROTOCOLS:
        # Protocols don't change between ethertypes, but we want to get
        # them all, from all ethertypes
        for ether_str, ethertype in ETHERTYPES.iteritems():
            for proto, proto_int in PROTOCOLS[ethertype].iteritems():
                REVERSE_PROTOCOLS[proto_int] = proto.upper()

    if not REVERSE_ETHERTYPES:
        for ether_str, ethertype in ETHERTYPES.iteritems():
            REVERSE_ETHERTYPES[ethertype] = ether_str


_init_protocols()
