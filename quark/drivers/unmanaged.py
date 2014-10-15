# Copyright 2013 Openstack Foundation
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

from neutron.openstack.common import log as logging

from quark import network_strategy
from quark.security_groups import redis_client


STRATEGY = network_strategy.STRATEGY
LOG = logging.getLogger(__name__)


class UnmanagedDriver(object):
    """Unmanaged network driver.

    Returns a bridge...
    """
    def __init__(self):
        self.load_config()

    def load_config(self):
        LOG.info("load_config")

    @classmethod
    def get_name(klass):
        return "UNMANAGED"

    def get_connection(self):
        LOG.info("get_connection")

    def create_network(self, context, network_name, tags=None,
                       network_id=None, **kwargs):
        LOG.info("create_network %s %s %s" % (context, network_name,
                                              tags))

    def delete_network(self, context, network_id):
        LOG.info("delete_network %s" % network_id)

    def diag_network(self, context, network_id, **kwargs):
        LOG.info("diag_network %s" % network_id)
        return {}

    def create_port(self, context, network_id, port_id, **kwargs):
        LOG.info("create_port %s %s %s" % (context.tenant_id, network_id,
                                           port_id))
        bridge_name = STRATEGY.get_network(context, network_id)["bridge"]
        return {"uuid": port_id, "bridge": bridge_name}

    def update_port(self, context, port_id, **kwargs):
        LOG.info("update_port %s %s" % (context.tenant_id, port_id))

        if "security_groups" in kwargs:
            client = redis_client.Client(use_master=True)
            payload = client.serialize(kwargs["security_groups"])
            client.apply_rules(kwargs["device_id"], kwargs["mac_address"],
                               payload)

        return {"uuid": port_id}

    def delete_port(self, context, port_id, **kwargs):
        LOG.info("delete_port %s %s" % (context.tenant_id, port_id))

    def diag_port(self, context, network_id, **kwargs):
        LOG.info("diag_port %s" % network_id)
        return {}

    def create_security_group(self, context, group_name, **group):
        LOG.info("Creating security profile %s for tenant %s" %
                 (group_name, context.tenant_id))

    def delete_security_group(self, context, group_id, **kwargs):
        LOG.info("Deleting security profile %s for tenant %s" %
                 (group_id, context.tenant_id))

    def update_security_group(self, context, group_id, **kwargs):
        LOG.info("Updating security profile %s for tenant %s" %
                 (group_id, context.tenant_id))

    def create_security_group_rule(self, context, group_id, rule):
        LOG.info("Creating security rule on group %s for tenant %s" %
                 (group_id, context.tenant_id))

    def delete_security_group_rule(self, context, group_id, rule):
        LOG.info("Deleting security rule on group %s for tenant %s" %
                 (group_id, context.tenant_id))
