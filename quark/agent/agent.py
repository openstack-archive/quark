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

import random
import time

from neutron.openstack.common import log as logging
from oslo.config import cfg

from quark.agent import redis_client as redis
from quark.agent import version_control
from quark.agent import xapi

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

agent_opts = [
    cfg.IntOpt("polling_interval",
               default=10,
               help=_("Number of seconds to wait between poll iterations of "
                      "XAPI and Redis."))
]

CONF.register_opts(agent_opts, "AGENT")


def _sleep():
    # NOTE(amir): add randomness to polling so all machines don't slam
    #             Redis at once
    time.sleep(CONF.AGENT.polling_interval + random.random() * 2)


def run():
    redis_client = redis.RedisClient()
    xapi_client = xapi.XapiClient()
    vc = version_control.VersionControl()

    instances = set()
    interfaces = set()
    while True:
        try:
            new_instances = xapi_client.get_instances()
            new_interfaces = xapi_client.get_interfaces(new_instances)
        except Exception:
            LOG.exception("Unable to get instances/interfaces from xapi")
            _sleep()
            continue

        new_instances = set(new_instances.values())
        added_instances = new_instances - instances
        removed_instances = instances - new_instances
        if added_instances or removed_instances:
            LOG.debug("instances: added %s removed %s",
                      added_instances, removed_instances)

        added_interfaces = new_interfaces - interfaces
        removed_interfaces = interfaces - new_interfaces
        if added_interfaces or removed_interfaces:
            LOG.debug("interfaces: added %s removed %s",
                      added_interfaces, removed_interfaces)

        try:
            new_security_groups = redis_client.get_security_groups(
                new_interfaces)
            added_sg, updated_sg, removed_sg = vc.diff(new_security_groups)
            xapi.update_interfaces(new_instances,
                                   added_sg, updated_sg, removed_sg)
        except Exception:
            LOG.exception("Unable to get security groups from Redis and apply"
                          " them to xapi")
            _sleep()
            continue

        vc.commit(new_security_groups)

        instances = new_instances
        interfaces = new_interfaces
        _sleep()
