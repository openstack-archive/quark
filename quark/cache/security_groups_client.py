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
#

import json
import uuid

import netaddr
from neutron.openstack.common import log as logging

from quark.cache import redis_base
from quark import exceptions as q_exc
from quark import protocols
from quark import utils


LOG = logging.getLogger(__name__)
SECURITY_GROUP_VERSION_UUID_KEY = "id"
SECURITY_GROUP_RULE_KEY = "rules"
SECURITY_GROUP_HASH_ATTR = "security group rules"


class SecurityGroupsClient(redis_base.ClientBase):
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
            if rule["remote_ip_prefix"]:
                if direction == "ingress":
                    source = netaddr.IPNetwork(rule["remote_ip_prefix"])
                    source = str(source.ipv6())
                else:
                    destination = netaddr.IPNetwork(
                        rule["remote_ip_prefix"])
                    destination = str(destination.ipv6())

            optional_fields = {}

            # NOTE(mdietz): this will expand as we add more protocols
            if rule["protocol"] == protocols.PROTOCOLS["icmp"]:
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
                       "direction": "ingress"}
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
          ]
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
          ]
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
        if not self._use_master:
            raise q_exc.RedisSlaveWritesForbidden()

        ruleset_uuid = str(uuid.uuid4())
        rule_dict = {SECURITY_GROUP_VERSION_UUID_KEY: ruleset_uuid,
                     SECURITY_GROUP_RULE_KEY: rules}
        redis_key = self.vif_key(device_id, mac_address)
        self.set_field(redis_key, SECURITY_GROUP_HASH_ATTR, rule_dict)

    def delete_vif_rules(self, device_id, mac_address):
        # Redis DEL command will ignore key safely if it doesn't exist
        self.delete_field(self.vif_key(device_id, mac_address),
                          SECURITY_GROUP_HASH_ATTR)

    @utils.retry_loop(3)
    def get_security_groups(self, new_interfaces):
        """Gets security groups for interfaces from Redis

        Returns a dictionary of xapi.VIFs mapped to security group version
        UUIDs from a set of xapi.VIF.
        """
        LOG.debug("Getting security groups from Redis for {0}".format(
            new_interfaces))
        new_interfaces = tuple(new_interfaces)
        vif_keys = [self.vif_key(vif.device_id, vif.mac_address)
                    for vif in new_interfaces]
        security_groups = self.get_fields(vif_keys, SECURITY_GROUP_HASH_ATTR)

        ret = {}
        for vif, security_group in zip(new_interfaces, security_groups):
            security_group_uuid = None
            if security_group:
                security_group_uuid = json.loads(security_group).get(
                    SECURITY_GROUP_VERSION_UUID_KEY)
            ret[vif] = security_group_uuid
        return ret
