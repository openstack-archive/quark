# Copyright 2014 Openstack Foundation
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

import errno
import json

from neutron.openstack.common import log as logging
from oslo.config import cfg

from quark.agent.xapi import VIF


LOG = logging.getLogger(__name__)
CONF = cfg.CONF

agent_opts = [
    cfg.StrOpt("version_control_path",
               default="./security_group_version_control.json",
               help=_("Path to local JSON file to contain security group "
                      "version metadata for each virtual interface."))
]

CONF.register_opts(agent_opts, "AGENT")


def _open_or_create_file_for_reading(path):
    try:
        the_file = open(path, "rb")
    except IOError as e:
        if e.errno == errno.ENOENT:
            LOG.info("Creating file [%s]", path)
            the_file = open(path, "wb+")
            json.dump({}, the_file)
            the_file.seek(0)
        else:
            LOG.exception("Unable to open file [%s]", path)
            raise
    return the_file


class VersionControl(object):
    def __init__(self):
        self._path = CONF.AGENT.version_control_path

    def diff(self, new_security_groups):
        """Processes diff between new_security_groups and VC file

        Returns tuple of length three. First element is a list of
        VIFs with added security groups. Second element is a list of VIFs
        with updated security groups. The last element is a list of VIFs with
        removed security groups.

        Added security groups are formed by VIFs present in the
        `new_security_groups` argument that are not present in the VC file.

        Updated security groups are formed by having different
        security UUIDs for a given VIF between the `new_security_groups`
        argument and the VC file.

        Removed security groups are formed by VIFs not present in the
        `new_security_groups` argument that are present in the VC file.
        """
        added_sg, updated_sg, removed_sg = [], [], []

        version_file = _open_or_create_file_for_reading(self._path)
        raw_security_groups = json.load(version_file)
        version_file.close()

        old_security_groups = dict(
            [(VIF.from_string(sgs), version)
             for sgs, version in raw_security_groups.iteritems()])

        vifs = set(old_security_groups.keys() + new_security_groups.keys())
        for vif in vifs:
            old_version = old_security_groups.get(vif)
            new_version = new_security_groups.get(vif)
            if not new_version:
                removed_sg.append(vif)
            elif not old_version:
                added_sg.append(vif)
            elif new_version != old_version:
                updated_sg.append(vif)

        return added_sg, updated_sg, removed_sg

    def commit(self, new_security_groups):
        """Saves `new_security_groups` to VC file."""

        added_sg, updated_sg, removed_sg = self.diff(new_security_groups)
        if not (added_sg or updated_sg or removed_sg):
            return

        LOG.debug("committing + %s ~ %s - %s" % (
            added_sg, updated_sg, removed_sg))

        version_file = open(self._path, "wb")
        security_groups = dict(
            [(str(sgs), version)
             for sgs, version in new_security_groups.iteritems()])
        json.dump(security_groups, version_file)
        version_file.close()
