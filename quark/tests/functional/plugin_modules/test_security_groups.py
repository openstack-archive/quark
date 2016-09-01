# Copyright 2016 Rackspace Hosting Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for# the specific language governing permissions and limitations
#  under the License.

import mock
# import netaddr

import contextlib

# from neutron.common import exceptions as q_exc
from oslo_config import cfg
from oslo_log import log as logging

from quark.db import api as db_api
from quark import environment as env
import quark.plugin_modules.mac_address_ranges as macrng_api
import quark.plugin_modules.networks as network_api
import quark.plugin_modules.ports as port_api
import quark.plugin_modules.security_groups as sg_api
import quark.plugin_modules.subnets as subnet_api
from quark.tests.functional.base import BaseFunctionalTest


LOG = logging.getLogger(__name__)


class SecurityGroupsAsyncUpdateTests(BaseFunctionalTest):
    def setUp(self):
        super(SecurityGroupsAsyncUpdateTests, self).setUp()
        env_set = [
            env.Capabilities.SECURITY_GROUPS,
            env.Capabilities.TENANT_NETWORK_SG,
            env.Capabilities.EGRESS,
            env.Capabilities.SG_UPDATE_ASYNC
        ]
        override = ','.join(env_set)
        self.old_override = cfg.CONF.QUARK.environment_capabilities
        cfg.CONF.set_override("environment_capabilities",
                              override,
                              "QUARK")
        self.dev_id = 0

    def _get_devid(self):
        self.dev_id += 1
        return self.dev_id

    def tearDown(self):
        super(SecurityGroupsAsyncUpdateTests, self).tearDown()
        cfg.CONF.set_override("environment_capabilities",
                              self.old_override,
                              "QUARK")

    def _make_body(self, net):
        port_info = {"port": dict(network_id=net['id'], tenant_id="fake",
                                  device_id=self._get_devid())}
        return port_info

    def _get_assoc_ports(self, sgid):
        db_sg = db_api.security_group_find(
            self.context, id=sgid, scope=db_api.ONE)
        self.assertIsNotNone(db_sg)
        return db_api.sg_gather_associated_ports(self.context, db_sg)

    @contextlib.contextmanager
    def _stubs(self, network_info, subnet_v4_info, subnet_v6_info=None):
        cls = 'QuarkSGAsyncProcessClient'
        mod_path = 'quark.worker_plugins.sg_update_worker.%s' % cls
        job_path = 'quark.plugin_modules.jobs'
        with mock.patch("neutron.common.rpc.get_notifier"), \
                mock.patch("neutron.quota.QUOTAS.limit_check"), \
                mock.patch("%s.add_job_to_context" % job_path), \
                mock.patch("%s.start_update" % mod_path) as update:
            self.context.is_admin = True
            net = network_api.create_network(self.context, network_info)
            mac = {'mac_address_range': dict(cidr="AA:BB:CC")}
            macrng_api.create_mac_address_range(self.context, mac)
            self.context.is_admin = False
            subnet_v4_info['subnet']['network_id'] = net['id']
            sub_v4 = subnet_api.create_subnet(self.context, subnet_v4_info)

            yield net, sub_v4, update

    def test_gather_sg_ports(self):
        """Checking if gather ports works as designed. """
        cidr = "192.168.1.0/24"
        network = dict(id='1', name="public", tenant_id="make",
                       network_plugin="BASE",
                       ipam_strategy="ANY")
        network = {"network": network}
        subnet_v4 = dict(id='1', ip_version=4, cidr=cidr,
                         tenant_id="fake")
        subnet_v4_info = {"subnet": subnet_v4}

        with self._stubs(network, subnet_v4_info) as (net, sub_v4, update):
            port1 = port_api.create_port(self.context, self._make_body(net))
            self.assertIsNotNone(port1)
            port2 = port_api.create_port(self.context, self._make_body(net))
            self.assertIsNotNone(port2)

            sg_body = dict(tenant_id="derp", name="test sg",
                           description="none")
            sg_body = dict(security_group=sg_body)

            sg = sg_api.create_security_group(self.context, sg_body)
            self.assertIsNotNone(sg)
            sgid = sg['id']
            self.assertIsNotNone(sgid)

            assoc_ports = self._get_assoc_ports(sgid)
            self.assertEqual(0, len(assoc_ports))

            port_body = {'security_groups': [sgid]}
            port_body = dict(port=port_body)

            port1 = port_api.update_port(self.context, port1['id'], port_body)
            self.assertIsNotNone(port1)

            assoc_ports = self._get_assoc_ports(sgid)
            self.assertEqual(1, len(assoc_ports))

            # NOTE: this is duplicated because update_port modifies the params
            port_body = {'security_groups': [sgid]}
            port_body = dict(port=port_body)

            port2 = port_api.update_port(self.context, port2['id'], port_body)
            self.assertIsNotNone(port2)

            assoc_ports = self._get_assoc_ports(sgid)
            self.assertEqual(2, len(assoc_ports))

    def test_env_caps_off_sg_async_update(self):
        """This test ensures that envcaps off works as designed."""
        env_set = [
            env.Capabilities.SECURITY_GROUPS,
            env.Capabilities.TENANT_NETWORK_SG,
            env.Capabilities.EGRESS,
        ]
        override = ','.join(env_set)
        old_override = cfg.CONF.QUARK.environment_capabilities
        cfg.CONF.set_override("environment_capabilities",
                              override,
                              "QUARK")
        cidr = "192.168.1.0/24"
        network = dict(id='1', name="public", tenant_id="make",
                       network_plugin="BASE",
                       ipam_strategy="ANY")
        network = {"network": network}
        subnet_v4 = dict(id='1', ip_version=4, cidr=cidr,
                         tenant_id="fake")
        subnet_v4_info = {"subnet": subnet_v4}

        try:
            with self._stubs(network, subnet_v4_info) as (net, sub_v4, update):
                port1 = port_api.create_port(
                    self.context, self._make_body(net))
                self.assertIsNotNone(port1)

                sg_body = dict(tenant_id="derp", name="test sg",
                               description="none")
                sg_body = dict(security_group=sg_body)

                sg = sg_api.create_security_group(self.context, sg_body)
                self.assertIsNotNone(sg)
                sgid = sg['id']
                self.assertIsNotNone(sgid)

                port_body = {'security_groups': [sgid]}
                port_body = dict(port=port_body)

                port1 = port_api.update_port(self.context, port1['id'],
                                             port_body)
                self.assertIsNotNone(port1)

                sgr_body = {'protocol': 'tcp', 'security_group_id': sgid,
                            'tenant_id': "derp",
                            'direction': 'ingress'}
                sgr_body = dict(security_group_rule=sgr_body)
                sgr = sg_api.create_security_group_rule(self.context, sgr_body)
                self.assertIsNotNone(sgr)
                self.assertFalse(update.called)
        finally:
            cfg.CONF.set_override("environment_capabilities",
                                  old_override,
                                  "QUARK")

    def test_env_caps_on_sg_async_update(self):
        """This test ensures that envcaps on works as designed."""
        env_set = [
            env.Capabilities.SECURITY_GROUPS,
            env.Capabilities.TENANT_NETWORK_SG,
            env.Capabilities.EGRESS,
            env.Capabilities.SG_UPDATE_ASYNC
        ]
        override = ','.join(env_set)
        old_override = cfg.CONF.QUARK.environment_capabilities
        cfg.CONF.set_override("environment_capabilities",
                              override,
                              "QUARK")
        cidr = "192.168.1.0/24"
        network = dict(id='1', name="public", tenant_id="make",
                       network_plugin="BASE",
                       ipam_strategy="ANY")
        network = {"network": network}
        subnet_v4 = dict(id='1', ip_version=4, cidr=cidr,
                         tenant_id="fake")
        subnet_v4_info = {"subnet": subnet_v4}

        try:
            with self._stubs(network, subnet_v4_info) as (net, sub_v4, update):
                port1 = port_api.create_port(
                    self.context, self._make_body(net))
                self.assertIsNotNone(port1)

                sg_body = dict(tenant_id="derp", name="test sg",
                               description="none")
                sg_body = dict(security_group=sg_body)

                sg = sg_api.create_security_group(self.context, sg_body)
                self.assertIsNotNone(sg)
                sgid = sg['id']
                self.assertIsNotNone(sgid)

                port_body = {'security_groups': [sgid]}
                port_body = dict(port=port_body)

                port1 = port_api.update_port(self.context, port1['id'],
                                             port_body)

                sgr_body = {'protocol': 'tcp', 'security_group_id': sgid,
                            'tenant_id': "derp",
                            'direction': 'ingress'}
                sgr_body = dict(security_group_rule=sgr_body)
                sgr = sg_api.create_security_group_rule(self.context, sgr_body)
                self.assertIsNotNone(sgr)
                self.assertTrue(update.called)
        finally:
            cfg.CONF.set_override("environment_capabilities",
                                  old_override,
                                  "QUARK")
