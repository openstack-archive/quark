import mock
import netaddr

from quark.db import api as db_api
from quark.tests.functional.mysql.base import MySqlBaseFunctionalTest
from quark.tools import null_routes


class TestNullRoutes(MySqlBaseFunctionalTest):
    def setUp(self):
        super(TestNullRoutes, self).setUp()
        self.cidr = "192.168.10.0/24"
        self.sub_cidr = "192.168.10.1/32"

    def test_get_subnets_cidr_set(self):
        network = db_api.network_create(self.context)
        db_api.subnet_create(
            self.context,
            network=network, cidr=self.cidr)
        self.context.session.flush()
        ipset = null_routes.get_subnets_cidr_set(self.context, [network.id])
        self.assertEqual(ipset, netaddr.IPSet(netaddr.IPNetwork(self.cidr)))

    @mock.patch("requests.get")
    def test_get_null_routes_addresses(self, get_method):
        url, region = "TEST_URL", "TEST_REGION"
        ipset = netaddr.IPSet(netaddr.IPNetwork(self.cidr))
        payload = [{
            "status": "1",
            "note": None,
            "updated": None,
            "name": None,
            "status_name": None,
            "region.id": region,
            "ip": None,
            "idql": None,
            "discovered": None,
            "netmask": None,
            "tag": None,
            "conf": None,
            "cidr": self.sub_cidr,
            "id": None,
            "switch.hostname": None,
        }]
        body = [{
            "paginate": {
                "total_count": len(payload),
                "total_count_display": None,
                "total_pages": None,
                "author_comment": None,
                "per_page": None,
                "page": None
            },
            "request": None,
            "payload": payload,
            "response": None
        }]
        get_method.return_value.json.return_value = body
        addresses = null_routes.get_null_routes_addresses(url, region, ipset)
        get_method.assert_called_once_with(url, verify=False)
        self.assertEqual(addresses,
                         netaddr.IPSet(netaddr.IPNetwork(self.sub_cidr)))

    def test_delete_locks_has_lock(self):
        network = db_api.network_create(self.context)
        address_model = db_api.ip_address_create(
            self.context,
            address=netaddr.IPAddress("192.168.10.1"),
            network=network)
        db_api.lock_holder_create(
            self.context, address_model,
            name=null_routes.LOCK_NAME, type="ip_address")
        self.context.session.flush()

        null_routes.delete_locks(self.context, [network.id], [])
        self.context.session.refresh(address_model)
        self.assertIsNone(address_model.lock_id)

    def test_delete_locks_doesnt_have_lock(self):
        network = db_api.network_create(self.context)
        address_model = db_api.ip_address_create(
            self.context,
            address=netaddr.IPAddress("192.168.10.1"),
            network=network)
        db_api.lock_holder_create(
            self.context, address_model,
            name="not-null-routes", type="ip_address")
        self.context.session.flush()

        null_routes.delete_locks(self.context, [network.id], [])
        self.context.session.refresh(address_model)
        self.assertIsNotNone(address_model.lock_id)

    def test_create_locks_address_doesnt_exist(self):
        network = db_api.network_create(self.context)
        subnet = db_api.subnet_create(
            self.context,
            network=network,
            cidr=self.cidr,
            ip_version=4)
        self.context.session.flush()

        addresses = netaddr.IPSet(netaddr.IPNetwork(self.sub_cidr))
        null_routes.create_locks(self.context, [network.id], addresses)
        address = db_api.ip_address_find(
            self.context, subnet_id=subnet.id, scope=db_api.ONE)
        self.assertIsNotNone(address)
        self.assertIsNotNone(address.lock_id)

    def test_create_locks_address_exists(self):
        network = db_api.network_create(self.context)
        address_model = db_api.ip_address_create(
            self.context,
            address=netaddr.IPAddress("192.168.10.1"),
            network=network)
        self.context.session.flush()

        addresses = netaddr.IPSet(netaddr.IPNetwork(self.sub_cidr))
        null_routes.create_locks(self.context, [network.id], addresses)
        self.context.session.refresh(address_model)
        self.assertIsNotNone(address_model.lock_id)

    def test_create_locks_lock_holder_exists(self):
        network = db_api.network_create(self.context)
        address_model = db_api.ip_address_create(
            self.context,
            address=netaddr.IPAddress("192.168.10.1"),
            network=network)
        db_api.lock_holder_create(
            self.context, address_model,
            name=null_routes.LOCK_NAME, type="ip_address")
        self.context.session.flush()

        addresses = netaddr.IPSet(netaddr.IPNetwork(self.sub_cidr))
        null_routes.create_locks(self.context, [network.id], addresses)

        lock_holders = db_api.lock_holder_find(
            self.context,
            lock_id=address_model.lock_id,
            name=null_routes.LOCK_NAME,
            scope=db_api.ALL)
        self.assertEqual(len(lock_holders), 1)
