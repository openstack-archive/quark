# Copyright 2013 Openstack LLC.
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

from quantum.openstack.common import log as logging

LOG = logging.getLogger("quantum.quark.base")


class BaseDriver(object):
    """
    Base interface for all Quark drivers. Usable as a replacement
    for the sample plugin
    """
    def load_config(self, path):
        LOG.info("load_config %s" % path)

    def get_connection(self):
        LOG.info("get_connection")

    def create_network(self, tenant_id, network_name, tags=None,
                       network_id=None, **kwargs):
        LOG.info("create_network %s %s %s" % (tenant_id, network_name,
                                              tags))

    def delete_network(self, context, network_id):
        LOG.info("delete_network %s" % network_id)

    def create_port(self, context, network_id, port_id, status=True):
        LOG.info("create_port %s %s %s" % (context.tenant_id, network_id,
                                           port_id))
        return {"uuid": port_id}

    def delete_port(self, context, port_id, lswitch_uuid=None):
        LOG.info("delete_port %s %s" % (context.tenant_id, port_id))
