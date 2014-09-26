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

import json

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

    def __init__(self, device_id, mac_address):
        """Constructs VIF

        `device_id` and `mac_address` should be strings if they will later be
        compared to decoded VIF instances (via from_string).
        """

        self.device_id = device_id
        self.mac_address = mac_address

    def __str__(self):
        return "%s%s%s" % (self.device_id, self.SEPARATOR, self.mac_address)

    @classmethod
    def from_string(cls, s):
        device_id, mac_address = s.split(cls.SEPARATOR)
        return cls(device_id, mac_address)

    def __repr__(self):
        return "VIF(%r, %r)" % (self.device_id, self.mac_address)

    def __eq__(self, other):
        return (self.device_id == other.device_id and
                self.mac_address == other.mac_address)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash((self.device_id, self.mac_address))


class XapiClient(object):
    SECURITY_GROUPS_KEY = "failmode"
    SECURITY_GROUPS_VALUE = "secure"

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
        for rec in recs.values():
            device_id = instances.get(rec["VM"])
            if not device_id:
                continue
            interfaces.add(VIF(device_id, rec["MAC"]))
        return interfaces

    def _process_security_groups(self, session, vm_ref, vif, fn):
        """Process security groups setting on VM's Xenstore for VIF.

        Based on the argument function, VM Opaque Ref, and VIF, we set the
        appropriate VM's Xenstore data to enable security groups or disable
        security groups for the correct VIF.
        """
        vm = session.xenapi.VM.get_record(vm_ref)
        location = ('vm-data/networking/%s' %
                    vif.mac_address.replace(':', ''))
        xsdata = json.loads(vm["xenstore_data"][location])

        # Update Xenstore dict based on fn
        fn(xsdata)

        # Update param Xenstore
        session.xenapi.VM.remove_from_xenstore_data(
            vm_ref, location)
        session.xenapi.VM.add_to_xenstore_data(
            vm_ref, location, json.dumps(xsdata))

        # Update running VM's Xenstore
        args = dict(host_uuid=self._host_uuid,
                    path=location,
                    value=json.dumps(xsdata),
                    dom_id=session.xenapi.VM.get_domid(vm_ref))
        if not args["dom_id"] or args["dom_id"] == -1:
            # If the VM is not running, no need to update the live Xenstore
            return

        session.xenapi.host.call_plugin(
            self._host_ref, "xenstore.py", "write_record", args)

    def _set_security_groups(self, session, vm_refs, interfaces):
        LOG.debug("Setting security groups on %s", interfaces)

        for interface in interfaces:
            vm_ref = vm_refs[interface.device_id]
            self._process_security_groups(
                session,
                vm_ref,
                interface,
                lambda d: d.update({self.SECURITY_GROUPS_KEY:
                                    self.SECURITY_GROUPS_VALUE}))

    def _unset_security_groups(self, session, vm_refs, interfaces):
        LOG.debug("Unsetting security groups on %s", interfaces)

        for interface in interfaces:
            vm_ref = vm_refs[interface.device_id]
            self._process_security_groups(
                session,
                vm_ref,
                interface,
                lambda d: d.pop(self.SECURITY_GROUPS_KEY, None))

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
        vm_refs = dict((v, k) for k, v in instances.iteritems())
        try:
            self._set_security_groups(session, vm_refs, added_sg)
            self._unset_security_groups(session, vm_refs, removed_sg)
            self._refresh_interfaces(session,
                                     added_sg + updated_sg + removed_sg)
        finally:
            session.xenapi.logout()
