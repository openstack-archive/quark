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

"""
Unicorn driver for Quark
"""

import requests

from oslo.config import cfg
from oslo_log import log as logging

from quark import exceptions as ex

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

quark_router_opts = [
    cfg.StrOpt('floating_ip_base_url',
               default='http://localhost:8080/v1.0/floating_ips',
               help=_('floating ips base url'))
]

CONF.register_opts(quark_router_opts, "QUARK")


class UnicornDriver(object):
    def __init__(self):
        pass

    @classmethod
    def get_name(cls):
        return "Unicorn"

    def register_floating_ip(self, floating_ip):
        pass

    def update_floating_ip(self, floating_ip):
        pass

    def remove_floating_ip(self, floating_ip):
        url = "%s/%s" % (CONF.QUARK.floating_ip_base_url,
                         floating_ip.formatted())

        LOG.info("Calling unicorn to remove floating ip: %s" % url)
        r = requests.delete(url)

        if r.status_code != 204:
            msg = "Unexpected status from unicorn API: Status Code %s, " \
                  "Message: %s" % (r.status_code,)
            LOG.error("remove_floating_ip: %s" % msg)
            raise ex.RemoveFloatingIpFailure(id=floating_ip["id"], msg=msg)
