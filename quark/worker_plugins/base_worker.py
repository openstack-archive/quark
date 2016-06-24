# Copyright 2016 Rackspace Hosting Inc.
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
from neutron.common import rpc as n_rpc
from neutron import context
from oslo_config import cfg
from oslo_log import log as logging


CONF = cfg.CONF
LOG = logging.getLogger(__name__)
TEST_TOPIC = 'quark'


class QuarkAsyncPluginBase(object):
    versions = []

    def __init__(self, topic):
        self._context = None
        self.topic = topic
        self.endpoints = []
        self.callbacks = []

    def _setup_rpc(self):
        self.endpoints.extend(self.callbacks)

    def start_rpc_listeners(self):
        """Configure all listeners here"""
        self._setup_rpc()
        if not self.endpoints:
            return []
        self.conn = n_rpc.create_connection()
        self.conn.create_consumer(self.topic, self.endpoints,
                                  fanout=False)
        return self.conn.consume_in_threads()

    @property
    def context(self):
        if not self._context:
            self._context = context.get_admin_context()
        return self._context


def get_test_context():
    return context.get_admin_context()
