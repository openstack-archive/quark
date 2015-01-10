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

from neutron.openstack.common import log as logging
from oslo.config import cfg
import XenAPI


LOG = logging.getLogger(__name__)
CONF = cfg.CONF

agent_opts = [
    cfg.StrOpt("xapi_connection_url"),
    cfg.StrOpt("xapi_connection_username", default="root"),
    cfg.StrOpt("xapi_connection_password")
]

CONF.register_opts(agent_opts, "AGENT")


class VIF(object):
    SEPARATOR = "."

    def __init__(self, device_id, mac_address, ref):
        """Constructs VIF

        `device_id` and `mac_address` should be strings if they will later be
        compared to decoded VIF instances (via from_string).

        `ref` is the OpaqueRef string for the vif as returned from xenapi.
        """

        self.device_id = device_id
        self.mac_address = mac_address
        self.ref = ref

    def __str__(self):
        return "%s%s%s%s%s" % (self.device_id, self.SEPARATOR,
                               self.mac_address, self.SEPARATOR,
                               self.ref)

    @classmethod
    def from_string(cls, s):
        device_id, mac_address, ref = s.split(cls.SEPARATOR)
        return cls(device_id, mac_address, ref)

    def __repr__(self):
        return "VIF(%r, %r, %r)" % (self.device_id, self.mac_address,
                                    self.ref)

    def __eq__(self, other):
        return (self.device_id == other.device_id and
                self.mac_address == other.mac_address)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash((self.device_id, self.mac_address))


class XapiClient(object):
    SECURITY_GROUPS_KEY = "security_groups"
    SECURITY_GROUPS_VALUE = "enabled"

    def __init__(self):
        session = self._session()
        try:
            self._host_ref = session.xenapi.session.get_this_host(
                session.handle)
            self._host_uuid = session.xenapi.host.get_uuid(self._host_ref)
        finally:
            session.xenapi.logout()

    def _session(self):
        LOG.debug("Created new Xapi session")

        session = XenAPI.Session(CONF.AGENT.xapi_connection_url)
        session.login_with_password(CONF.AGENT.xapi_connection_username,
                                    CONF.AGENT.xapi_connection_password)
        return session

    def get_instances(self):
        """Returns a dict of `VM OpaqueRef` (str) -> `device_id` (str)."""
        LOG.debug("Getting instances from Xapi")

        session = self._session()
        try:
            recs = session.xenapi.VM.get_all_records()
        finally:
            session.xenapi.logout()

        # NOTE(asadoughi): Copied from xen-networking-scripts/utils.py
        is_inst = lambda r: (r['power_state'].lower() == 'running' and
                             not r['is_a_template'] and
                             not r['is_control_domain'] and
                             ('nova_uuid' in r['other_config'] or
                              r['name_label'].startswith('instance-')))
        instances = dict()
        for vm_ref, rec in recs.iteritems():
            if not is_inst(rec):
                continue
            instances[vm_ref] = rec["other_config"]["nova_uuid"]
        return instances

    def get_interfaces(self, instances):
        """Returns a set of VIFs from `get_instances` return value."""
        LOG.debug("Getting interfaces from Xapi")

        session = self._session()
        try:
            recs = session.xenapi.VIF.get_all_records()
        finally:
            session.xenapi.logout()

        interfaces = set()
        for vif_ref, rec in recs.iteritems():
            device_id = instances.get(rec["VM"])
            if not device_id:
                continue
            interfaces.add(VIF(device_id, rec["MAC"], vif_ref))
        return interfaces

    def _set_security_groups(self, session, interfaces):
        LOG.debug("Setting security groups on %s", interfaces)

        for vif in interfaces:
            session.xenapi.VIF.add_to_other_config(
                vif.ref,
                self.SECURITY_GROUPS_KEY,
                self.SECURITY_GROUPS_VALUE)

    def _unset_security_groups(self, session, interfaces):
        LOG.debug("Unsetting security groups on %s", interfaces)

        for vif in interfaces:
            session.xenapi.VIF.remove_from_other_config(
                vif.ref,
                self.SECURITY_GROUPS_KEY)

    def _refresh_interfaces(self, session, interfaces):
        LOG.debug("Refreshing devices on %s", interfaces)

        device_ids = set([vif.device_id for vif in interfaces])
        for device_id in device_ids:
            args = {"host_uuid": self._host_uuid, "uuid": device_id}
            session.xenapi.host.call_plugin(
                self._host_ref,
                "post_live_migrate",
                "instance_post_live_migration",
                args)

    def update_interfaces(self, instances, added_sg, updated_sg, removed_sg):
        """Handles changes to interfaces' security groups

        Calls refresh_interfaces on argument VIFs. Set security groups on
        added_sg's VIFs. Unsets security groups on removed_sg's VIFs.
        """
        if not (added_sg or updated_sg or removed_sg):
            return

        session = self._session()
        try:
            self._set_security_groups(session, added_sg)
            self._unset_security_groups(session, removed_sg)
            combined = added_sg + updated_sg + removed_sg
            self._refresh_interfaces(session, combined)
        finally:
            session.xenapi.logout()
