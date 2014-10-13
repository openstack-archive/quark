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
from oslo.config import cfg
import redis
import redis.sentinel

from quark import exceptions as q_exc

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

quark_opts = [
    cfg.StrOpt('redis_security_groups_host',
               default='127.0.0.1',
               help=_("The server to write security group rules to")),
    cfg.IntOpt('redis_security_groups_port',
               default=6379,
               help=_("The port for the redis server")),
    cfg.BoolOpt("redis_use_sentinels",
                default=False,
                help=_("Tell the redis client to use sentinels rather than a "
                       "direct connection")),
    cfg.ListOpt("redis_sentinel_hosts",
                default=["localhost:26397"],
                help=_("Comma-separated list of host:port pairs for Redis "
                       "sentinel hosts")),
    cfg.StrOpt("redis_sentinel_master",
               default='',
               help=_("The name label of the master redis sentinel")),
    cfg.BoolOpt("redis_use_ssl",
                default=False,
                help=_("Configures whether or not to use SSL")),
    cfg.StrOpt("redis_ssl_certfile",
               default='',
               help=_("Path to the SSL cert")),
    cfg.StrOpt("redis_ssl_keyfile",
               default='',
               help=_("Path to the SSL keyfile")),
    cfg.StrOpt("redis_ssl_ca_certs",
               default='',
               help=_("Path to the SSL CA certs"))]

CONF.register_opts(quark_opts, "QUARK")


class Client(object):
    def __init__(self):
        host = CONF.QUARK.redis_security_groups_host
        port = CONF.QUARK.redis_security_groups_port

        # NOTE: this is a naive implementation. The redis module
        #       also supports connection pooling, which may be necessary
        #       going forward, but we'll roll with this for now.
        try:
            if CONF.QUARK.redis_use_sentinels:
                host, port = self._discover_master_sentinel()

            kwargs = {"host": host, "port": port}
            if CONF.QUARK.redis_use_ssl:
                kwargs["ssl"] = True
                if CONF.QUARK.redis_ssl_certfile:
                    kwargs["ssl_certfile"] = CONF.QUARK.redis_ssl_certfile
                    kwargs["ssl_cert_reqs"] = "required"
                    kwargs["ssl_ca_certs"] = CONF.QUARK.redis_ssl_ca_certs
                    kwargs["ssl_keyfile"] = CONF.QUARK.redis_ssl_keyfile

            self._client = redis.StrictRedis(**kwargs)
        except redis.ConnectionError as e:
            LOG.exception(e)
            raise q_exc.SecurityGroupsCouldNotBeApplied()

    def _discover_master_sentinel(self):
        sentinel_list = [tuple(host.split(':'))
                         for host in CONF.QUARK.redis_sentinel_hosts]
        if not sentinel_list:
            raise TypeError("sentinel_list is not a properly formatted list "
                            "of 'host:port' pairs")

        sentinel = redis.sentinel.Sentinel(sentinel_list)
        host, port = sentinel.discover_master(CONF.QUARK.redis_sentinel_master)
        return host, port

    def serialize(self, groups):
        """Creates a payload for the redis server

        The rule schema is the following:

        REDIS KEY - port_device_id.port_mac_address
        REDIS VALUE - A JSON dump of the following:

        {"id": "<arbitrary uuid>",
         "rules": [
           {"ethertype": <hexademical integer>,
            "protocol": <integer>,
            "port start": <integer>,
            "port end": <integer>,
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
        """

        rule_uuid = str(uuid.uuid4())
        rule_dict = {"id": rule_uuid, "rules": []}

        # TODO(mdietz): If/when we support other rule types, this comment
        #               will have to be revised.
        # Action and direction are static, for now. The implementation may
        # support 'deny' and 'egress' respectively in the future. We allow
        # the direction to be set to something else, technically, but current
        # plugin level call actually raises. It's supported here for unit
        # test purposes at this time
        for group in groups:
            for rule in group.rules:
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

                rule_dict["rules"].append(
                    {"ethertype": rule["ethertype"],
                     "protocol": rule["protocol"],
                     "port start": rule["port_range_min"],
                     "port end": rule["port_range_max"],
                     "source network": source,
                     "destination network": destination,
                     "action": "allow",
                     "direction": "ingress"})

        return rule_dict

    def rule_key(self, device_id, mac_address):
        return "{0}.{1}".format(device_id, str(netaddr.EUI(mac_address)))

    def apply_rules(self, device_id, mac_address, rules):
        """Writes a series of security group rules to a redis server."""
        redis_key = self.rule_key(device_id, mac_address)
        try:
            self._client.set(redis_key, json.dumps(rules))
        except redis.ConnectionError as e:
            LOG.exception(e)
            raise q_exc.SecurityGroupsCouldNotBeApplied()
