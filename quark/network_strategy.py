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
#    under the License.

import json

from oslo_config import cfg
from oslo_log import log as logging

LOG = logging.getLogger(__name__)
CONF = cfg.CONF

quark_opts = [
    cfg.StrOpt('default_net_strategy', default='{}',
               help=_("Default network assignment strategy"))
]
CONF.register_opts(quark_opts, "QUARK")


class JSONStrategy(object):
    def __init__(self, strategy=None):
        self.reverse_strategy = {}
        self.strategy = {}
        if not strategy:
            self._compile_strategy(CONF.QUARK.default_net_strategy)
        else:
            self._compile_strategy(strategy)

    def _compile_strategy(self, strategy):
        self.strategy = json.loads(strategy)

    def split_network_ids(self, context, net_ids):
        assignable = []
        tenant = []
        for net_id in net_ids:
            if self.is_provider_network(net_id):
                assignable.append(net_id)
            else:
                tenant.append(net_id)
        return tenant, assignable

    def get_network(self, context, net_id):
        return self.strategy.get(net_id)

    def get_assignable_networks(self, context):
        return self.strategy.keys()

    def is_provider_network(self, net_id):
        return self.strategy.get(net_id) is not None


STRATEGY = JSONStrategy()
