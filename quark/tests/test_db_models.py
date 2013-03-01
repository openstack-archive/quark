from collections import namedtuple
from sqlalchemy import create_engine

from quantum.db import api as db_api

from quark.db import models
import quark.plugin

import test_base


class TestSubnets(test_base.TestBase):
    def setUp(self):
        db_api._ENGINE = create_engine('sqlite://')
        db_api.register_models()
        self.session = db_api.get_session()
        self.plugin = quark.plugin.Plugin()

    def test_allocated_ips_only(self):
        MockContext = namedtuple('MockContext', ['tenant_id', 'session'])
        context = MockContext('0', self.session)

        # 1. Create network
        network = {'network': {'name': 'test'}}
        response = self.plugin.create_network(context, network)
        network_id = response['id']

        # 2. Create subnet
        subnet = {'subnet': {'cidr': '192.168.10.1/24',
                             'network_id': network_id}}
        self.plugin.create_subnet(context, subnet)

        # 3. Create M.A.R.
        mac_range = {'mac_address_range': {'cidr': '01:23:45/24'}}
        self.plugin.create_mac_address_range(context, mac_range)

        # 4. Create port
        port = {'port': {'network_id': network_id,
                         'device_id': ''}}
        response = self.plugin.create_port(context, port)

        q = self.session.query(models.Subnet).outerjoin(models.IPAddress)
        self.assertEqual(len(q.first().allocated_ips),
                         1)

        # 5. Delete port.
        self.plugin.delete_port(context, response['id'])

        q = self.session.query(models.Subnet).outerjoin(models.IPAddress)
        self.assertEqual(len(q.first().allocated_ips),
                         0)
