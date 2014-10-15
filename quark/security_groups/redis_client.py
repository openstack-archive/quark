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
    connection_pool = None

    def __init__(self, use_master=False):
        self._ensure_connection_pool_exists()
        self._sentinel_list = None
        self._use_master = use_master

        try:
            if CONF.QUARK.redis_use_sentinels:
                self._client = self._client_from_sentinel(self._use_master)
            else:
                self._client = self._client_from_config()

        except redis.ConnectionError as e:
            LOG.exception(e)
            raise q_exc.RedisConnectionFailure()

    def _ensure_connection_pool_exists(self):
        if not Client.connection_pool:
            LOG.info("Creating redis connection pool for the first time...")
            connect_class = redis.Connection
            connect_kw = {}
            if CONF.QUARK.redis_use_ssl:
                LOG.info("Communicating with redis over SSL")
                connect_class = redis.SSLConnection
                connect_kw["ssl"] = True
                if CONF.QUARK.redis_ssl_certfile:
                    connect_kw["ssl_certfile"] = CONF.QUARK.redis_ssl_certfile
                    connect_kw["ssl_cert_reqs"] = "required"
                    connect_kw["ssl_ca_certs"] = CONF.QUARK.redis_ssl_ca_certs
                    connect_kw["ssl_keyfile"] = CONF.QUARK.redis_ssl_keyfile

            klass = redis.ConnectionPool
            if CONF.QUARK.redis_use_sentinels:
                klass = redis.sentinel.SentinelConnectionPool

            Client.connection_pool = klass(connection_class=connect_class,
                                           **connect_kw)

    def _get_sentinel_list(self):
        if not self._sentinel_list:
            self._sentinel_list = [tuple(host.split(':'))
                                   for host in CONF.QUARK.redis_sentinel_hosts]
            if not self._sentinel_list:
                raise TypeError("sentinel_list is not a properly formatted"
                                "list of 'host:port' pairs")

        return self._sentinel_list

    def _client_from_config(self):
        host = CONF.QUARK.redis_security_groups_host
        port = CONF.QUARK.redis_security_groups_port
        LOG.info("Initializing redis connection %s:%s" % (host, port))
        kwargs = {"host": host, "port": port,
                  "connection_pool": Client.connection_pool}
        return redis.StrictRedis(**kwargs)

    def _client_from_sentinel(self, is_master=True):
        master = is_master and "master" or "slave"
        LOG.info("Initializing redis connection to %s node, master label %s" %
                 (master, CONF.QUARK.redis_sentinel_master))

        sentinel = redis.sentinel.Sentinel(self._get_sentinel_list())
        func = sentinel.slave_for
        if is_master:
            func = sentinel.master_for

        return func(CONF.QUARK.redis_sentinel_master,
                    connection_pool=Client.connection_pool)

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
        LOG.info("Applying security group rules for device %s with MAC %s" %
                 (device_id, mac_address))
        if not self._use_master:
            raise q_exc.RedisSlaveWritesForbidden()

        redis_key = self.rule_key(device_id, mac_address)
        try:
            self._client.set(redis_key, json.dumps(rules))
        except redis.ConnectionError as e:
            LOG.exception(e)
            raise q_exc.RedisConnectionFailure()
