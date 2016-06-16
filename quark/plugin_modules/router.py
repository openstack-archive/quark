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

from oslo_config import cfg
from oslo_log import log as logging

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

quark_router_opts = [
    cfg.StrOpt('floating_ip_router_id',
               default='00000000-0000-0000-0000-000000000000',
               help=_('floating ips default public router id'))
]

CONF.register_opts(quark_router_opts, "QUARK")


def get_router(context, id, fields):
    LOG.info("get_router %s for tenant %s fields %s" %
             (id, context.tenant_id, fields))
    if id != CONF.QUARK.floating_ip_router_id:
        return None

    return _get_floating_ip_default_router(context.tenant_id)


def get_routers(context, filters=None, fields=None, sorts=None, limit=None,
                marker=None, page_reverse=False):
    LOG.info("get_routers for tenant %s filters %s fields %s" %
             (context.tenant_id, filters, fields))
    return [_get_floating_ip_default_router(context.tenant_id)]


def _get_floating_ip_default_router(tenant_id):
    return {"id": CONF.QUARK.floating_ip_router_id,
            "status": "ACTIVE",
            "tenant_id": tenant_id,
            "name": "Floating IP Public Router",
            "admin_state_up": True}
