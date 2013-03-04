from collections import namedtuple
from sqlalchemy import create_engine

from oslo.config import cfg
from quantum import context
from quantum.db import api as db_api

from quark.db import models
import quark.plugin

import test_base


class TestSubnets(test_base.TestBase):
    def setUp(self):
        cfg.CONF.set_override('sql_connection', 'sqlite://', 'DATABASE')
        db_api.configure_db()
        self.context = context.get_admin_context()
        self.plugin = quark.plugin.Plugin()

    def test_allocated_ips_only(self):
        # 1. Create network
        network = {'network': {'name': 'test'}}
        response = self.plugin.create_network(self.context, network)
        network_id = response['id']

        # 2. Create subnet
        subnet = {'subnet': {'cidr': '192.168.10.1/24',
                             'network_id': network_id}}
        self.plugin.create_subnet(self.context, subnet)

        # 3. Create M.A.R.
        mac_range = {'mac_address_range': {'cidr': '01:23:45/24'}}
        self.plugin.create_mac_address_range(self.context, mac_range)

        # 4. Create port
        port = {'port': {'network_id': network_id,
                         'device_id': ''}}
        response = self.plugin.create_port(self.context, port)

        q = self.context.session.query(models.Subnet).outerjoin(
            models.IPAddress)
        self.assertEqual(len(q.first().allocated_ips),
                         1)

        # 5. Delete port.
        self.plugin.delete_port(self.context, response['id'])

        q = self.context.session.query(models.Subnet).outerjoin(
            models.IPAddress)
        self.assertEqual(len(q.first().allocated_ips),
                         0)

    def tearDown(self):
        db_api.clear_db()
