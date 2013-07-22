# Copyright (c) 2012 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from neutron import quota
from oslo.config import cfg


CONF = cfg.CONF


quark_opts = [
    cfg.StrOpt('net_driver',
               default='quark.drivers.base.BaseDriver',
               help=_('The client to use to talk to the backend')),
    cfg.StrOpt('ipam_driver', default='quark.ipam.QuarkIpam',
               help=_('IPAM Implementation to use')),
    cfg.BoolOpt('ipam_reuse_after', default=7200,
                help=_("Time in seconds til IP and MAC reuse"
                       "after deallocation.")),
    cfg.StrOpt("strategy_driver",
               default='quark.network_strategy.JSONStrategy',
               help=_("Tree of network assignment strategy")),
    cfg.StrOpt('net_driver_cfg', default='/etc/neutron/quark.ini',
               help=_("Path to the config for the net driver"))
]

quark_quota_opts = [
    cfg.IntOpt('quota_ports_per_network',
               default=64,
               help=_('Maximum ports per network per tenant')),
    cfg.IntOpt('quota_security_rules_per_group',
               default=20,
               help=_('Maximum security group rules in a group')),
]

quark_resources = [
    quota.BaseResource('ports_per_network',
                       'quota_ports_per_network'),
    quota.BaseResource('security_rules_per_group',
                       'quota_security_rules_per_group'),
]

CONF.register_opts(quark_opts, "QUARK")
CONF.register_opts(quark_quota_opts, "QUOTAS")

quota.QUOTAS.register_resources(quark_resources)
