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

import functools
import json
import string

import netaddr
from oslo_config import cfg
from oslo_log import log as logging

from quark import exceptions as q_exc

from twiceredis import TwiceRedis


CONF = cfg.CONF
LOG = logging.getLogger(__name__)
MAC_TRANS_TABLE = string.maketrans(string.ascii_uppercase,
                                   string.ascii_lowercase)

quark_opts = [
    cfg.ListOpt("redis_sentinel_hosts",
                default=["localhost:26397"],
                help=_("Comma-separated list of host:port pairs for Redis "
                       "sentinel hosts")),
    cfg.StrOpt("redis_sentinel_master",
               default='',
               help=_("The name label of the master redis sentinel")),
    cfg.StrOpt("redis_password",
               default='',
               help=_("The password for authenticating with redis.")),
    cfg.StrOpt("redis_db",
               default="0",
               help=("The database number to use")),
    cfg.FloatOpt("redis_socket_timeout",
                 default=0.1,
                 help=("Timeout for Redis socket operations"))]

CONF.register_opts(quark_opts, "QUARK")

# TODO(mdietz): Rewrite this to use a module level connection
#               pool, and then incorporate that into creating
#               connections. When connecting to a master we
#               connect by creating a redis client, and when
#               we connect to a slave, we connect by telling it
#               we want a slave and ending up with a connection,
#               with no control over SSL or anything else.  :-|


def handle_connection_error(fn):
    @functools.wraps(fn)
    def wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except TwiceRedis.generic_error as e:
            LOG.exception(e)
            raise q_exc.RedisConnectionFailure()
    return wrapped


class ClientBase(object):
    def __init__(self):
        self._client = self.get_redis_client()

    def get_redis_client(self):
        sentinels = [tuple(str.split(host_pair, ':'))
                     for host_pair in CONF.QUARK.redis_sentinel_hosts]

        pool_kwargs = TwiceRedis.DEFAULT_POOL_KWARGS
        sentinel_kwargs = TwiceRedis.DEFAULT_SENTINEL_KWARGS
        pool_kwargs['socket_timeout'] = CONF.QUARK.redis_socket_timeout
        pool_kwargs['socket_keepalive'] = False
        sentinel_kwargs['min_other_sentinels'] = 2
        return TwiceRedis(master_name=CONF.QUARK.redis_sentinel_master,
                          sentinels=sentinels,
                          password=CONF.QUARK.redis_password,
                          pool_kwargs=pool_kwargs,
                          sentinel_kwargs=sentinel_kwargs)

    def vif_key(self, device_id, mac_address):
        mac = str(netaddr.EUI(mac_address))

        # Lower cases and strips hyphens from the mac
        mac = mac.translate(MAC_TRANS_TABLE, ":-")
        return "{0}.{1}".format(device_id, mac)

    @handle_connection_error
    def ping(self):
        # NOTE(tr3buchet): if this gets used by anything other than the
        #                  redis_sg_tool, self._client.disconnect()
        #                  needs to be called before returning
        return self._client.master.ping() and self._client.slave.ping()

    @handle_connection_error
    def vif_keys(self, field=None):
        keys = self._client.slave.keys("*.????????????")
        filtered = []
        if isinstance(keys, str):
            keys = [keys]
        with self._client.slave.pipeline() as pipe:
            for key in keys:
                value = None
                if field:
                    value = pipe.hget(key, field)
                else:
                    value = pipe.hgetall(key)
            values = pipe.execute()
        for value in values:
            if value:
                filtered.append(key)
        return filtered

    @handle_connection_error
    def set_field(self, key, field, data):
        self.set_field_raw(key, field, json.dumps(data))

    @handle_connection_error
    def set_field_raw(self, key, field, data):
        self._client.master.hset(key, field, data)
        self._client.master.disconnect()

    @handle_connection_error
    def get_field(self, key, field):
        return self._client.slave.hget(key, field)

    @handle_connection_error
    def delete_field(self, key, field):
        self._client.master.hdel(key, field)
        self._client.master.disconnect()

    @handle_connection_error
    def delete_key(self, key):
        self._client.master.delete(key)
        self._client.master.disconnect()

    @handle_connection_error
    def get_fields(self, keys, field):
        with self._client.slave.pipeline() as pipe:
            for key in keys:
                pipe.hget(key, field)
            values = pipe.execute()
        return values

    @handle_connection_error
    def set_fields(self, keys, field, value):
        with self._client.master.pipeline() as pipe:
            for key in keys:
                pipe.hset(key, field, value)
            pipe.execute()
        self._client.master.disconnect()
