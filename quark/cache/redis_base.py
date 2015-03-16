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

import functools
import json
import string

import netaddr
from oslo.config import cfg
from oslo_log import log as logging
import redis
import redis.sentinel

from quark import exceptions as q_exc


CONF = cfg.CONF
LOG = logging.getLogger(__name__)
MAC_TRANS_TABLE = string.maketrans(string.ascii_uppercase,
                                   string.ascii_lowercase)

quark_opts = [
    cfg.StrOpt('redis_host',
               default='127.0.0.1',
               help=_("The server to write redis data to or"
                      " retrieve sentinel information from, as appropriate")),
    cfg.IntOpt('redis_port',
               default=6379,
               help=_("The port for the redis server to write redis data to or"
                      " retrieve sentinel information from, as appropriate")),
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
        except redis.ConnectionError as e:
            LOG.exception(e)
            raise q_exc.RedisConnectionFailure()
    return wrapped


class ClientBase(object):
    read_connection_pool = None
    write_connection_pool = None

    def __init__(self, use_master=False):
        self._use_master = use_master
        try:
            if CONF.QUARK.redis_use_sentinels:
                self._compile_sentinel_list()
            self._ensure_connection_pools_exist()
            self._client = self._client()
        except redis.ConnectionError as e:
            LOG.exception(e)
            raise q_exc.RedisConnectionFailure()

    def _prepare_pool_connection(self, master):
        LOG.info("Creating redis connection pool for the first time...")
        host = CONF.QUARK.redis_host
        port = CONF.QUARK.redis_port

        connect_args = []
        connect_kw = {}
        if CONF.QUARK.redis_password:
            connect_kw["password"] = CONF.QUARK.redis_password

        if CONF.QUARK.redis_use_sentinels:
            LOG.info("Using redis sentinel connections %s" %
                     self._sentinel_list)
            klass = redis.sentinel.SentinelConnectionPool
            connect_args.append(CONF.QUARK.redis_sentinel_master)
            connect_args.append(redis.sentinel.Sentinel(self._sentinel_list))
            connect_kw["check_connection"] = True
            connect_kw["is_master"] = master
        else:
            LOG.info("Using redis host %s:%s" % (host, port))
            klass = redis.ConnectionPool
            connect_kw["host"] = host
            connect_kw["port"] = port

        return klass, connect_args, connect_kw

    def _ensure_connection_pools_exist(self):
        if not (ClientBase.write_connection_pool or
                ClientBase.read_connection_pool):
            klass, args, kwargs = self._prepare_pool_connection(master=False)
            ClientBase.read_connection_pool = klass(*args, **kwargs)

            klass, args, kwargs = self._prepare_pool_connection(master=True)
            ClientBase.write_connection_pool = klass(*args, **kwargs)

    def _compile_sentinel_list(self):
        self._sentinel_list = [tuple(host.split(':'))
                               for host in CONF.QUARK.redis_sentinel_hosts]
        if not self._sentinel_list:
            raise TypeError("sentinel_list is not a properly formatted"
                            "list of 'host:port' pairs")

    def _client(self):
        pool = ClientBase.read_connection_pool
        if self._use_master:
            pool = ClientBase.write_connection_pool

        kwargs = {"connection_pool": pool,
                  "db": CONF.QUARK.redis_db,
                  "socket_timeout": CONF.QUARK.redis_socket_timeout}
        return redis.StrictRedis(**kwargs)

    def vif_key(self, device_id, mac_address):
        mac = str(netaddr.EUI(mac_address))

        # Lower cases and strips hyphens from the mac
        mac = mac.translate(MAC_TRANS_TABLE, ":-")
        return "{0}.{1}".format(device_id, mac)

    @handle_connection_error
    def echo(self, echo_str):
        return self._client.echo(echo_str)

    @handle_connection_error
    def vif_keys(self, field=None):
        keys = self._client.keys("*.????????????")
        filtered = []
        if isinstance(keys, str):
            keys = [keys]
        for key in keys:
            value = None
            if field:
                value = self._client.hget(key, field)
            else:
                value = self._client.hgetall(key)
            if value:
                filtered.append(key)
        return filtered

    @handle_connection_error
    def set_field(self, key, field, data):
        return self.set_field_raw(key, field, json.dumps(data))

    @handle_connection_error
    def set_field_raw(self, key, field, data):
        return self._client.hset(key, field, data)

    @handle_connection_error
    def get_field(self, key, field):
        return self._client.hget(key, field)

    @handle_connection_error
    def delete_field(self, key, field):
        return self._client.hdel(key, field)

    @handle_connection_error
    def delete_key(self, key):
        return self._client.delete(key)

    @handle_connection_error
    def get_fields(self, keys, field):
        p = self._client.pipeline()
        for key in keys:
            p.hget(key, field)
        return p.execute()

    @handle_connection_error
    def set_fields(self, keys, field, value):
        p = self._client.pipeline()
        for key in keys:
            p.hset(key, field, value)
        return p.execute()
