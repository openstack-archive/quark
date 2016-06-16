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

from collections import namedtuple
import contextlib

from oslo_config import cfg
from oslo_log import log as logging
import XenAPI


LOG = logging.getLogger(__name__)
CONF = cfg.CONF

agent_opts = [
    cfg.StrOpt("xapi_connection_url"),
    cfg.StrOpt("xapi_connection_username", default="root"),
    cfg.IntOpt("xapi_enable_groups_retries", default=5),
    cfg.StrOpt("xapi_connection_password")
]

CONF.register_opts(agent_opts, "AGENT")
SECURITY_GROUPS_KEY = "security_groups"
VM = namedtuple('VM', ['ref', 'uuid', 'vifs', 'dom_id'])


class VIF(object):
    SEPARATOR = "."

    def __init__(self, device_id, record, ref):
        """Constructs VIF

        `device_id` and `mac_address` should be strings if they will later be
        compared to decoded VIF instances (via from_string).

        `ref` is the OpaqueRef string for the vif as returned from xenapi.
        """

        self.device_id = device_id
        self.record = record
        self.ref = ref
        self.success = False

    def __str__(self):
        return "%s%s%s%s%s" % (self.device_id, self.SEPARATOR,
                               self.mac_address, self.SEPARATOR,
                               self.ref)

    @property
    def mac_address(self):
        return self.record["MAC"]

    @property
    def tagged(self):
        return self.record["other_config"].get(SECURITY_GROUPS_KEY)

    @classmethod
    def from_string(cls, s):
        device_id, mac_address, ref = s.split(cls.SEPARATOR)
        return cls(device_id, mac_address, ref)

    def succeed(self):
        self.success = True

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
    SECURITY_GROUPS_VALUE = "enabled"

    def __init__(self):
        with self.sessioned() as session:
            self._host_ref = session.xenapi.session.get_this_host(
                session.handle)
            self._host_uuid = session.xenapi.host.get_uuid(self._host_ref)

    def _session(self):
        LOG.debug("Created new Xapi session")

        session = XenAPI.Session(CONF.AGENT.xapi_connection_url)
        session.login_with_password(CONF.AGENT.xapi_connection_username,
                                    CONF.AGENT.xapi_connection_password)
        return session

    @contextlib.contextmanager
    def sessioned(self):
        session = None
        try:
            session = self._session()
            yield session
        except Exception:
            LOG.exception("Failed to create a XAPI session")
            raise
        finally:
            if session is not None:
                session.xenapi.session.logout()

    def get_instances(self, session):
        """Returns a dict of `VM OpaqueRef` (str) -> `xapi.VM`."""
        LOG.debug("Getting instances from Xapi")

        recs = session.xenapi.VM.get_all_records()

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
            instances[vm_ref] = VM(ref=vm_ref,
                                   uuid=rec["other_config"]["nova_uuid"],
                                   vifs=rec["VIFs"],
                                   dom_id=rec["domid"])
        return instances

    def get_interfaces(self):
        """Returns a set of VIFs from `get_instances` return value."""
        LOG.debug("Getting interfaces from Xapi")

        with self.sessioned() as session:
            instances = self.get_instances(session)
            recs = session.xenapi.VIF.get_all_records()

        interfaces = set()
        for vif_ref, rec in recs.iteritems():
            vm = instances.get(rec["VM"])
            if not vm:
                continue
            device_id = vm.uuid
            interfaces.add(VIF(device_id, rec, vif_ref))
        return interfaces

    def _set_security_groups(self, session, interfaces):
        LOG.debug("Setting security groups on %s", interfaces)

        for vif in interfaces:
            try:
                session.xenapi.VIF.add_to_other_config(
                    vif.ref, SECURITY_GROUPS_KEY,
                    self.SECURITY_GROUPS_VALUE)
            except XenAPI.Failure:
                # We shouldn't lose all of them because one failed
                # An example of a continuable failure is the VIF was deleted
                # in the (albeit very small) window between the initial fetch
                # and here.
                LOG.exception("Failed to enable security groups for VIF "
                              "with MAC %s" % vif.mac_address)

    def _unset_security_groups(self, session, interfaces):
        LOG.debug("Unsetting security groups on %s", interfaces)

        for vif in interfaces:
            try:
                session.xenapi.VIF.remove_from_other_config(
                    vif.ref,
                    SECURITY_GROUPS_KEY)
            except XenAPI.Failure:
                # NOTE(mdietz): RM11399 - removing a parameter that doesn't
                #               exist is idempotent. Trying to remove it
                #               from a VIF that doesn't exist raises :-( This
                #               may be a consequence of bad data, but we should
                #               try to cover ourselves here and continue.
                LOG.exception("Failed to disable security groups for VIF "
                              "with MAC %s" % vif.mac_address)

    def _refresh_interfaces(self, session, interfaces):
        LOG.debug("Refreshing devices on %s", interfaces)

        for vif in interfaces:
            try:
                vif_rec = session.xenapi.VIF.get_record(vif.ref)
                vm_rec = session.xenapi.VM.get_record(vif_rec["VM"])
                vif_index = vif_rec["device"]
                dom_id = vm_rec["domid"]
                vif.succeed()
            except XenAPI.Failure:
                LOG.exception("Failure when looking up VMs or VIFs")
                continue

            args = {"dom_id": dom_id, "vif_index": vif_index}
            session.xenapi.host.call_plugin(
                self._host_ref,
                "neutron_vif_flow",
                "online_instance_flows",
                args)

    def update_interfaces(self, added_sg, updated_sg, removed_sg):
        """Handles changes to interfaces' security groups

        Calls refresh_interfaces on argument VIFs. Set security groups on
        added_sg's VIFs. Unsets security groups on removed_sg's VIFs.
        """
        if not (added_sg or updated_sg or removed_sg):
            return

        with self.sessioned() as session:
            self._set_security_groups(session, added_sg)
            self._unset_security_groups(session, removed_sg)
            combined = added_sg + updated_sg + removed_sg
            self._refresh_interfaces(session, combined)
