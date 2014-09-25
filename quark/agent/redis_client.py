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

import json

from neutron.openstack.common import log as logging
from oslo.config import cfg
from redis.sentinel import Sentinel

from quark.agent import utils


LOG = logging.getLogger(__name__)
CONF = cfg.CONF

agent_opts = [
    cfg.ListOpt("redis_sentinel_hosts",
                default=["localhost:26379"],
                help=_("Comma-separated list of host:port pairs for Redis "
                       "sentinel hosts.")),
    cfg.StrOpt("redis_sentinel_master",
               default="mymaster",
               help=_("Service name for Redis master.")),
    cfg.StrOpt("redis_db", default="0"),
    cfg.FloatOpt("redis_socket_timeout", default=0.1)
]

CONF.register_opts(agent_opts, "AGENT")

SECURITY_GROUP_VERSION_UUID_KEY = "uuid"


class RedisClient(object):
    def __init__(self):
        self._sentinels = [hostport.split(":")
                           for hostport in CONF.AGENT.redis_sentinel_hosts]
        self._sentinel_master = CONF.AGENT.redis_sentinel_master
        self._db = CONF.AGENT.redis_db
        self._socket_timeout = CONF.AGENT.redis_socket_timeout

    def _connection(self):
        sentinel = Sentinel(self._sentinels,
                            socket_timeout=self._socket_timeout)
        slave = sentinel.slave_for(self._sentinel_master,
                                   socket_timeout=self._socket_timeout,
                                   db=self._db)
        return slave

    @utils.retry_loop(3)
    def get_security_groups(self, new_interfaces):
        """Gets security groups for interfaces from Redis

        Returns a dictionary of xapi.VIFs mapped to security group version
        UUIDs from a set of xapi.VIF.
        """

        new_interfaces = tuple(new_interfaces)

        p = self._connection().pipeline()
        for vif in new_interfaces:
            p.get(str(vif))
        security_groups = p.execute()

        ret = {}
        for vif, security_group in zip(new_interfaces, security_groups):
            security_group_uuid = None
            if security_group:
                security_group_uuid = json.loads(security_group).get(
                    SECURITY_GROUP_VERSION_UUID_KEY)
            ret[vif] = security_group_uuid
        return ret
