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
#

import json

import netaddr
from oslo_config import cfg
from oslo_log import log as logging

from quark.cache import redis_base
from quark.environment import Capabilities
from quark import exceptions as q_exc
from quark import protocols
from quark import utils


CONF = cfg.CONF
LOG = logging.getLogger(__name__)
SECURITY_GROUP_RULE_KEY = "rules"
SECURITY_GROUP_HASH_ATTR = "security group rules"
SECURITY_GROUP_ACK = "security group ack"

ALL_V4 = netaddr.IPNetwork("::ffff:0.0.0.0/96")
ALL_V6 = netaddr.IPNetwork("::/0")


class SecurityGroupsClient(redis_base.ClientBase):
    def _convert_remote_network(self, remote_ip_prefix):
        # NOTE(mdietz): RM11364 - While a /0 is valid and should be supported,
        #               it breaks OVS to apply a /0 as the source or
        #               destination network.
        net = netaddr.IPNetwork(remote_ip_prefix).ipv6()
        if net.cidr == ALL_V4 or net.cidr == ALL_V6:
            return ''
        return str(net)

    def serialize_rules(self, rules):
        """Creates a payload for the redis server."""
        # TODO(mdietz): If/when we support other rule types, this comment
        #               will have to be revised.
        # Action and direction are static, for now. The implementation may
        # support 'deny' and 'egress' respectively in the future. We allow
        # the direction to be set to something else, technically, but current
        # plugin level call actually raises. It's supported here for unit
        # test purposes at this time
        serialized = []
        for rule in rules:
            direction = rule["direction"]
            source = ''
            destination = ''
            if rule.get("remote_ip_prefix"):
                prefix = rule["remote_ip_prefix"]
                if direction == "ingress":
                    source = self._convert_remote_network(prefix)
                else:
                    if (Capabilities.EGRESS not in
                            CONF.QUARK.environment_capabilities):
                        raise q_exc.EgressSecurityGroupRulesNotEnabled()
                    else:
                        destination = self._convert_remote_network(prefix)

            optional_fields = {}

            # NOTE(mdietz): this will expand as we add more protocols
            protocol_map = protocols.PROTOCOL_MAP[rule["ethertype"]]
            if rule["protocol"] == protocol_map["icmp"]:
                optional_fields["icmp type"] = rule["port_range_min"]
                optional_fields["icmp code"] = rule["port_range_max"]
            else:
                optional_fields["port start"] = rule["port_range_min"]
                optional_fields["port end"] = rule["port_range_max"]

            payload = {"ethertype": rule["ethertype"],
                       "protocol": rule["protocol"],
                       "source network": source,
                       "destination network": destination,
                       "action": "allow",
                       "direction": direction}
            payload.update(optional_fields)
            serialized.append(payload)
        return serialized

    def serialize_groups(self, groups):
        """Creates a payload for the redis server

        The rule schema is the following:

        REDIS KEY - port_device_id.port_mac_address/sg
        REDIS VALUE - A JSON dump of the following:

        port_mac_address must be lower-cased and stripped of non-alphanumeric
        characters

        {"id": "<arbitrary uuid>",
          "rules": [
            {"ethertype": <hexademical integer>,
             "protocol": <integer>,
             "port start": <integer>,  # optional
             "port end": <integer>,    # optional
             "icmp type": <integer>,   # optional
             "icmp code": <integer>,   # optional
             "source network": <string>,
             "destination network": <string>,
             "action": <string>,
             "direction": <string>},
          ],
          "security groups ack": <boolean>
        }

        Example:
        {"id": "004c6369-9f3d-4d33-b8f5-9416bf3567dd",
         "rules": [
           {"ethertype": 0x800,
            "protocol": "tcp",
            "port start": 1000,
            "port end": 1999,
            "source network": "10.10.10.0/24",
            "destination network": "",
            "action": "allow",
            "direction": "ingress"},
          ],
          "security groups ack": "true"
        }

        port start/end and icmp type/code are mutually exclusive pairs.
        """
        rules = []
        for group in groups:
            rules.extend(self.serialize_rules(group.rules))
        return rules

    def get_rules_for_port(self, device_id, mac_address):
        rules = self.get_field(
            self.vif_key(device_id, mac_address), SECURITY_GROUP_HASH_ATTR)
        if rules:
            return json.loads(rules)

    def apply_rules(self, device_id, mac_address, rules):
        """Writes a series of security group rules to a redis server."""
        LOG.info("Applying security group rules for device %s with MAC %s" %
                 (device_id, mac_address))

        rule_dict = {SECURITY_GROUP_RULE_KEY: rules}
        redis_key = self.vif_key(device_id, mac_address)
        # TODO(mdietz): Pipeline these. Requires some rewriting
        self.set_field(redis_key, SECURITY_GROUP_HASH_ATTR, rule_dict)
        self.set_field_raw(redis_key, SECURITY_GROUP_ACK, False)

    def delete_vif_rules(self, device_id, mac_address):
        # Redis HDEL command will ignore key safely if it doesn't exist
        self.delete_field(self.vif_key(device_id, mac_address),
                          SECURITY_GROUP_HASH_ATTR)
        self.delete_field(self.vif_key(device_id, mac_address),
                          SECURITY_GROUP_ACK)

    def delete_vif(self, device_id, mac_address):
        # Redis DEL command will ignore key safely if it doesn't exist
        self.delete_key(self.vif_key(device_id, mac_address))

    @utils.retry_loop(3)
    def get_security_group_states(self, interfaces):
        """Gets security groups for interfaces from Redis

        Returns a dictionary of xapi.VIFs with values of the current
        acknowledged status in Redis.

        States not explicitly handled:
        * ack key, no rules - This is the same as just tagging the VIF,
          the instance will be inaccessible
        * rules key, no ack - Nothing will happen, the VIF will
          not be tagged.
        """
        LOG.debug("Getting security groups from Redis for {0}".format(
            interfaces))
        interfaces = tuple(interfaces)
        vif_keys = [self.vif_key(vif.device_id, vif.mac_address)
                    for vif in interfaces]

        security_groups = self.get_fields(vif_keys, SECURITY_GROUP_ACK)

        ret = {}
        for vif, security_group_ack in zip(interfaces, security_groups):
            if security_group_ack:
                security_group_ack = security_group_ack.lower()
                if "true" in security_group_ack:
                    ret[vif] = True
                elif "false" in security_group_ack:
                    ret[vif] = False
                else:
                    LOG.debug("Skipping bad ack value %s" % security_group_ack)
        return ret

    @utils.retry_loop(3)
    def update_group_states_for_vifs(self, vifs, ack):
        """Updates security groups by setting the ack field"""
        vif_keys = [self.vif_key(vif.device_id, vif.mac_address)
                    for vif in vifs]
        self.set_fields(vif_keys, SECURITY_GROUP_ACK, ack)
