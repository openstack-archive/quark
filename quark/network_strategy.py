import json

from oslo.config import cfg
from quantum.common import exceptions
from quantum.openstack.common import log as logging

LOG = logging.getLogger("quantum.quark")
CONF = cfg.CONF

quark_opts = [
    cfg.StrOpt('default_net_strategy', default='{}',
               help=_("Default network assignment strategy"))
]
CONF.register_opts(quark_opts, "QUARK")


class JSONStrategy(object):
    def __init__(self):
        self.reverse_strategy = {}
        self.strategy = {}
        self._compile_strategy(CONF.QUARK.default_net_strategy)

    def _compile_strategy(self, strategy):
        strategy = json.loads(strategy)
        for network, definition in strategy.iteritems():
            for _, child_net in definition["children"].iteritems():
                self.reverse_strategy[child_net] = network
        self.strategy = strategy

    def split_network_ids(self, context, net_ids):
        assignable = []
        tenant = []
        for net_id in net_ids:
            if self.is_parent_network(net_id):
                assignable.append(net_id)
            else:
                tenant.append(net_id)
        return tenant, assignable

    def get_assignable_networks(self, context):
        return self.strategy.keys()

    def is_parent_network(self, net_id):
        return self.strategy.get(net_id) is not None

    def get_parent_network(self, net_id):
        net = self.reverse_strategy.get(net_id)
        if net:
            return net

        # No matches, this is the highest network
        return net_id

    def best_match_network_id(self, context, net_id, key):
        net = self.strategy.get(net_id)
        if net:
            child_net = net["children"].get(key)
            if not child_net:
                raise exceptions.NetworkNotFound(net_id=net_id)
            return child_net
        return net_id


STRATEGY = JSONStrategy()
