# Copyright 2013 Rackspace Hosting Inc.
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
# License for the specific language governing permissions and limitations
#  under the License.

import mock
import netaddr
from oslo_log import log as logging

from quark.db import api as db_api
from quark.db import models
from quark import tags
from quark.tests.functional.base import BaseFunctionalTest

LOG = logging.getLogger(__name__)


class TestDBAPI(BaseFunctionalTest):
    def setUp(self):
        super(TestDBAPI, self).setUp()

    def test_port_find_ip_address_id(self):
        self.context.session.query = mock.Mock()
        db_api.port_find(self.context, ip_address_id="fake")
        query_obj = self.context.session.query.return_value
        filter_fn = query_obj.options.return_value.filter
        self.assertEqual(filter_fn.call_count, 1)

    def test_ip_address_find_device_id(self):
        query_mock = mock.Mock()
        filter_mock = mock.Mock()

        self.context.session.query = query_mock
        query_mock.return_value = filter_mock

        db_api.ip_address_find(self.context, device_id="foo")
        self.assertEqual(filter_mock.filter.call_count, 1)

    def test_ip_address_find_address_type(self):
        self.context.session.query = mock.MagicMock()
        filter_mock = self.context.session.query.return_value

        db_api.ip_address_find(self.context, address_type="foo")
        # NOTE(thomasem): Creates sqlalchemy.sql.elements.BinaryExpression
        # when using SQLAlchemy models in expressions.
        tenant_filter = (models.IPAddress.used_by_tenant_id.in_(
                         [self.context.tenant_id]))
        type_filter = models.IPAddress.address_type == "foo"
        self.assertEqual(len(filter_mock.filter.call_args[0]), 2)
        # NOTE(thomasem): Unfortunately BinaryExpression.compare isn't
        # showing to be a reliable comparison, so using the string
        # representation which dumps the associated SQL for the filter.
        type_found = False
        tenant_found = False
        for model_filter in list(filter_mock.filter.call_args[0]):
            if str(type_filter) == str(model_filter):
                type_found = True
            elif str(tenant_filter) == str(model_filter):
                tenant_found = True
        self.assertTrue(tenant_found)
        self.assertTrue(type_found)

    def test_ip_address_find_port_id(self):
        self.context.session.query = mock.MagicMock()
        final_query_mock = self.context.session.query.return_value

        db_api.ip_address_find(self.context, port_id="foo")
        # NOTE(thomasem): Creates sqlalchemy.sql.elements.BinaryExpression
        # when using SQLAlchemy models in expressions.
        tenant_filter = (models.IPAddress.used_by_tenant_id.in_(
                         [self.context.tenant_id]))
        port_filter = models.IPAddress.ports.any(models.Port.id == "foo")
        self.assertEqual(len(final_query_mock.filter.call_args[0]), 2)
        port_found = False
        tenant_found = False
        for model_filter in list(final_query_mock.filter.call_args[0]):
            if str(port_filter) == str(model_filter):
                port_found = True
            elif str(tenant_filter) == str(model_filter):
                tenant_found = True
        self.assertTrue(tenant_found)
        self.assertTrue(port_found)

    def test_ip_address_find_address_type_as_admin(self):
        self.context.session.query = mock.MagicMock()
        filter_mock = self.context.session.query.return_value

        db_api.ip_address_find(self.context.elevated(), address_type="foo")
        # NOTE(thomasem): Creates sqlalchemy.sql.elements.BinaryExpression
        # when using SQLAlchemy models in expressions.
        expected_filter = models.IPAddress.address_type == "foo"
        self.assertEqual(len(filter_mock.filter.call_args[0]), 1)
        # NOTE(thomasem): Unfortunately BinaryExpression.compare isn't
        # showing to be a reliable comparison, so using the string
        # representation which dumps the associated SQL for the filter.
        self.assertEqual(str(expected_filter), str(
            filter_mock.filter.call_args[0][0]))

    def test_ip_address_find_port_id_as_admin(self):
        self.context.session.query = mock.MagicMock()
        final_query_mock = self.context.session.query.return_value

        db_api.ip_address_find(self.context.elevated(), port_id="foo")
        # NOTE(thomasem): Creates sqlalchemy.sql.elements.BinaryExpression
        # when using SQLAlchemy models in expressions.
        expected_filter = models.IPAddress.ports.any(models.Port.id == "foo")
        self.assertEqual(len(final_query_mock.filter.call_args[0]), 1)
        self.assertEqual(str(expected_filter), str(
            final_query_mock.filter.call_args[0][0]))

    def test_ip_address_find_ip_address_object(self):
        ip_address = netaddr.IPAddress("192.168.10.1")
        try:
            db_api.ip_address_find(self.context, ip_address=ip_address,
                                   scope=db_api.ONE)
        except Exception as e:
            self.fail("Expected no exceptions: %s" % e)

    def test_ip_address_find_ip_address_list(self):
        ip_address = netaddr.IPAddress("192.168.10.1")
        try:
            db_api.ip_address_find(self.context, ip_address=[ip_address],
                                   scope=db_api.ONE)
        except Exception as e:
            self.fail("Expected no exceptions: %s" % e)

    def test_model_query_with_IPAddress(self):
        # NOTE: tenant_id filter will always be added
        test_model = models.IPAddress
        good_filter = {"network_id": [2]}
        result = db_api._model_query(self.context, test_model, good_filter)
        self.assertEqual(len(result), 2)
        bad_filter = {"ethertype": "IPv4"}
        result = db_api._model_query(self.context, test_model, bad_filter)
        self.assertEqual(len(result), 1)

    def test_model_query_with_MacAddress(self):
        test_model = models.MacAddress
        good_filter = {"deallocated": True}
        result = db_api._model_query(self.context, test_model, good_filter)
        self.assertEqual(len(result), 2)
        bad_filter = {"protocol": "ICMP"}
        result = db_api._model_query(self.context, test_model, bad_filter)
        self.assertEqual(len(result), 1)

    def test_model_query_with_Network(self):
        test_model = models.Network
        good_filter = {"name": ["BOB"]}
        result = db_api._model_query(self.context, test_model, good_filter)
        self.assertEqual(len(result), 2)
        bad_filter = {"deallocated": True}
        result = db_api._model_query(self.context, test_model, bad_filter)
        self.assertEqual(len(result), 1)

    def test_model_query_with_Port(self):
        test_model = models.Port
        good_filter = {"device_id": [123]}
        result = db_api._model_query(self.context, test_model, good_filter)
        self.assertEqual(len(result), 2)
        bad_filter = {"not_real": "BANANAS"}
        result = db_api._model_query(self.context, test_model, bad_filter)
        self.assertEqual(len(result), 1)

    def test_model_query_with_SecurityGroup(self):
        test_model = models.SecurityGroup
        good_filter = {"name": ["Abraham Lincoln"]}
        result = db_api._model_query(self.context, test_model, good_filter)
        self.assertEqual(len(result), 2)
        bad_filter = {"segment_id": [123]}
        result = db_api._model_query(self.context, test_model, bad_filter)
        self.assertEqual(len(result), 1)

    def test_model_query_with_SecurityGroupRule(self):
        test_model = models.SecurityGroupRule
        good_filter = {"ethertype": ["IPv4"]}
        result = db_api._model_query(self.context, test_model, good_filter)
        self.assertEqual(len(result), 2)
        bad_filter = {"made_up": "Moon Landing"}
        result = db_api._model_query(self.context, test_model, bad_filter)
        self.assertEqual(len(result), 1)

    def test_model_query_with_Subnet(self):
        test_model = models.Subnet
        good_filter = {"network_id": [42]}
        result = db_api._model_query(self.context, test_model, good_filter)
        self.assertEqual(len(result), 2)
        bad_filter = {"subnet_id": [123]}
        result = db_api._model_query(self.context, test_model, bad_filter)
        self.assertEqual(len(result), 1)

    def test_port_associate_ip(self):
        self.context.session.add = mock.Mock()
        mock_ports = [models.Port(id=str(x), network_id="2", ip_addresses=[])
                      for x in xrange(4)]
        mock_address = models.IPAddress(id="1", address=3232235876,
                                        address_readable="192.168.1.100",
                                        subnet_id="1", network_id="2",
                                        version=4, used_by_tenant_id="1")
        r = db_api.port_associate_ip(self.context, mock_ports, mock_address)
        self.assertEqual(len(r.associations), len(mock_ports))
        for assoc, port in zip(r.associations, mock_ports):
            self.assertEqual(assoc.port, port)
            self.assertEqual(assoc.ip_address, mock_address)
            self.assertEqual(assoc.enabled, False)

    def test_port_associate_ip_enable_port(self):
        self.context.session.add = mock.Mock()
        mock_port = models.Port(id="1", network_id="2", ip_addresses=[])
        mock_address = models.IPAddress(id="1", address=3232235876,
                                        address_readable="192.168.1.100",
                                        subnet_id="1", network_id="2",
                                        version=4, used_by_tenant_id="1")
        r = db_api.port_associate_ip(self.context, [mock_port], mock_address,
                                     enable_port="1")
        self.assertEqual(len(r.associations), 1)
        assoc = r.associations[0]
        self.assertEqual(assoc.port, mock_port)
        self.assertEqual(assoc.ip_address, mock_address)
        self.assertEqual(assoc.enabled, True)
        self.context.session.add.assert_called_once_with(assoc)

    def test_port_disassociate_ip(self):
        self.context.session.add = mock.Mock()
        self.context.session.delete = mock.Mock()
        mock_ports = [models.Port(id=str(x), network_id="2", ip_addresses=[])
                      for x in xrange(4)]
        mock_address = models.IPAddress(id="1", address=3232235876,
                                        address_readable="192.168.1.100",
                                        subnet_id="1", network_id="2",
                                        version=4, used_by_tenant_id="1")
        mock_assocs = []
        for p in mock_ports:
            assoc = models.PortIpAssociation()
            assoc.port_id = p.id
            assoc.port = p
            assoc.ip_address_id = mock_address.id
            assoc.ip_address = mock_address
            mock_assocs.append(assoc)

        r = db_api.port_disassociate_ip(self.context, mock_ports[1:3],
                                        mock_address)

        self.assertEqual(len(r.associations), 2)
        self.assertEqual(r.associations[0], mock_assocs[0])
        self.assertEqual(r.associations[1], mock_assocs[3])
        self.context.session.add.assert_called_once_with(r)
        self.context.session.delete.assert_has_calls(
            [mock.call(mock_assocs[1]), mock.call(mock_assocs[2])])

    @mock.patch("quark.db.api.get_ports_for_address")
    @mock.patch("quark.db.api.port_disassociate_ip")
    @mock.patch("quark.db.api.port_associate_ip")
    def test_update_port_associations_for_ip(self, associate_mock,
                                             disassociate_mock,
                                             get_associations_mock):
        self.context.session.add = mock.Mock()
        self.context.session.delete = mock.Mock()
        mock_ports = [models.Port(id=str(x), network_id="2", ip_addresses=[])
                      for x in xrange(4)]
        mock_address = models.IPAddress(id="1", address=3232235876,
                                        address_readable="192.168.1.100",
                                        subnet_id="1", network_id="2",
                                        version=4, used_by_tenant_id="1")
        mock_address.ports = mock_ports
        new_port_list = mock_ports[1:3]
        new_port_list.append(models.Port(id="4", network_id="2",
                             ip_addresses=[]))
        get_associations_mock.return_value = mock_ports
        # NOTE(thomasem): Should be the new address after associating
        # any new ports in the list.
        mock_new_address = associate_mock.return_value

        db_api.update_port_associations_for_ip(self.context,
                                               new_port_list,
                                               mock_address)

        associate_mock.assert_called_once_with(self.context,
                                               set([new_port_list[2]]),
                                               mock_address)

        disassociate_mock.assert_called_once_with(self.context,
                                                  set([mock_ports[0],
                                                       mock_ports[3]]),
                                                  mock_new_address)

    def test_update_port_sets_vlan_tag(self):
        self.context.session.add = mock.Mock()
        mock_port = models.Port(id=1, network_id="2", ip_addresses=[], tags=[])
        db_api.port_update(self.context, mock_port, vlan_id=1)
        self.assertEqual(mock_port.tags, [tags.VlanTag().serialize(1)])

    def test_create_port_sets_vlan_tag(self):
        self.context.session.add = mock.Mock()
        port_req = {"id": 1, "network_id": "2", "vlan_id": 1}
        new_port = db_api.port_create(self.context, **port_req)
        self.assertEqual(new_port.tags, [tags.VlanTag().serialize(1)])
