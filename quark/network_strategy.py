# Copyright 2013 Rackspace Hosting Inc.
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
               help=_("Default network assignment strategy")),
    cfg.StrOpt('public_net_id', default='00000000-0000-0000-0000-000000000000',
               help=_("Public network id"))
]
CONF.register_opts(quark_opts, "QUARK")


class JSONStrategy(object):
    def __init__(self, strategy=None):
        self.subnet_strategy = {}
        self.strategy = {}
        self.load(strategy)

    def load(self, strategy=None):
        if not strategy:
            self._compile_strategy(CONF.QUARK.default_net_strategy)
        else:
            self._compile_strategy(strategy)

    def _compile_strategy(self, strategy):
        self.strategy = json.loads(strategy)
        for net_id, meta in self.strategy.iteritems():
            if "subnets" in meta:
                for ip_version, subnet_id in meta["subnets"].iteritems():
                    self.subnet_strategy[subnet_id] = {
                        "ip_version": ip_version,
                        "network_id": net_id}
            else:
                LOG.warning('net_id {} strategy has no "subnets" '
                            'metadata.'.format(net_id))

    def _split(self, func, resource_ids):
        provider = []
        tenant = []
        for res_id in resource_ids:
            if func(res_id):
                provider.append(res_id)
            else:
                tenant.append(res_id)
        return tenant, provider

    def split_network_ids(self, net_ids):
        return self._split(self.is_provider_network, net_ids)

    def split_subnet_ids(self, subnet_ids):
        return self._split(self.is_provider_subnet, subnet_ids)

    def get_provider_networks(self):
        return sorted(self.strategy.keys())

    def get_provider_subnets(self):
        return sorted(self.subnet_strategy.keys())

    def get_provider_subnet_id(self, net_id, ip_version):
        if net_id not in self.strategy:
            return None
        return self.strategy[net_id]["subnets"][str(ip_version)]

    def get_network(self, net_id):
        return self.strategy.get(net_id)

    def is_provider_network(self, net_id):
        return self.strategy.get(net_id) is not None

    def is_provider_subnet(self, subnet_id):
        return subnet_id in self.subnet_strategy

    def subnet_ids_for_network(self, net_id):
        if net_id in self.strategy:
            subnets = self.strategy.get(net_id)["subnets"]
            return [subnet_id for ip_version, subnet_id in subnets.iteritems()]

    def get_network_for_subnet(self, subnet_id):
        if subnet_id not in self.subnet_strategy:
            return None
        return self.subnet_strategy.get(subnet_id)["network_id"]

    def get_public_net_id(self):
        """Returns the public net id"""
        for id, net_params in self.strategy.iteritems():
            if id == CONF.QUARK.public_net_id:
                return id
        return None


STRATEGY = JSONStrategy()
