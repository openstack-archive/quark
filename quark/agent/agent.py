# Copyright 2014 Rackspace Hosting Inc.
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
import sys
import time

from neutron.common import config
from neutron.common import utils as n_utils
from oslo_config import cfg
from oslo_log import log as logging

from quark.agent import xapi
from quark.cache import security_groups_client as sg_cli

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

agent_opts = [
    cfg.IntOpt("polling_interval",
               default=10,
               help=_("Number of seconds to wait between poll iterations of "
                      "XAPI and the configured security groups registry."))
]

CONF.register_opts(agent_opts, "AGENT")


def _sleep():
    # NOTE(amir): add randomness to polling so all machines don't slam
    #             the security groups registry at once
    time.sleep(CONF.AGENT.polling_interval + random.random() * 2)


def is_isonet_vif(vif):
    """Determine if a vif is on isonet

    Returns True if a vif belongs to an isolated network by checking
    for a nicira interface id.
    """
    nicira_iface_id = vif.record.get('other_config').get('nicira-iface-id')

    if nicira_iface_id:
        return True

    return False


def partition_vifs(xapi_client, interfaces, security_group_states):
    """Splits VIFs into three explicit categories and one implicit

    Added - Groups exist in Redis that have not been ack'd and the VIF
            is not tagged.
            Action: Tag the VIF and apply flows
    Updated - Groups exist in Redis that have not been ack'd and the VIF
              is already tagged
              Action: Do not tag the VIF, do apply flows
    Removed - Groups do NOT exist in Redis but the VIF is tagged
              Action: Untag the VIF, apply default flows
    Self-Heal - Groups are ack'd in Redis but the VIF is untagged. We treat
                this case as if it were an "added" group.
                Action: Tag the VIF and apply flows
    NOOP - The VIF is not tagged and there are no matching groups in Redis.
           This is our implicit category
           Action: Do nothing
    """
    added = []
    updated = []
    removed = []

    for vif in interfaces:
        # Quark should not action on isonet vifs in regions that use FLIP
        if ('floating_ip' in CONF.QUARK.environment_capabilities and
                is_isonet_vif(vif)):
            continue

        vif_has_groups = vif in security_group_states
        if vif.tagged and vif_has_groups and security_group_states[vif]:
            # Already ack'd these groups and VIF is tagged, reapply.
            # If it's not tagged, fall through and have it self-heal
            continue

        if vif.tagged:
            if vif_has_groups:
                updated.append(vif)
            else:
                removed.append(vif)
        else:
            if vif_has_groups:
                added.append(vif)
            # if not tagged and no groups, skip

    return added, updated, removed


def ack_groups(client, groups):
    if len(groups) > 0:
        client.update_group_states_for_vifs(groups, True)


def run():
    """Fetches changes and applies them to VIFs periodically

    Process as of RM11449:
    * Get all groups from redis
    * Fetch ALL VIFs from Xen
    * Walk ALL VIFs and partition them into added, updated and removed
    * Walk the final "modified" VIFs list and apply flows to each
    """
    groups_client = sg_cli.SecurityGroupsClient()
    xapi_client = xapi.XapiClient()

    interfaces = set()
    while True:
        try:
            interfaces = xapi_client.get_interfaces()
        except Exception:
            LOG.exception("Unable to get instances/interfaces from xapi")
            _sleep()
            continue

        try:
            sg_states = groups_client.get_security_group_states(interfaces)
            new_sg, updated_sg, removed_sg = partition_vifs(xapi_client,
                                                            interfaces,
                                                            sg_states)
            xapi_client.update_interfaces(new_sg, updated_sg, removed_sg)
            groups_to_ack = [v for v in new_sg + updated_sg if v.success]
            ack_groups(groups_client, groups_to_ack)

        except Exception:
            LOG.exception("Unable to get security groups from registry and "
                          "apply them to xapi")
            _sleep()
            continue

        _sleep()


def main():
    config.init(sys.argv[1:])
    config.setup_logging()
    n_utils.log_opt_values(LOG)
    if not CONF.config_file:
        sys.exit(_("ERROR: Unable to find configuration file via the default"
                   " search paths (~/.neutron/, ~/, /etc/neutron/, /etc/) and"
                   " the '--config-file' option!"))
    run()
