import contextlib
import datetime
import os
import tempfile

from alembic import command as alembic_command
from alembic import config as alembic_config
import mock
import netaddr
import sqlalchemy as sa
from sqlalchemy import create_engine
from sqlalchemy import pool
from sqlalchemy.sql import column
from sqlalchemy.sql import select
from sqlalchemy.sql import table

from quark.db.custom_types import INET
import quark.db.migration
from quark.tests import test_base


class BaseMigrationTest(test_base.TestBase):
    def setUp(self):
        self.config = alembic_config.Config(
            os.path.join(quark.db.migration.__path__[0], 'alembic.ini'))
        self.config.set_main_option('script_location',
                                    'quark.db.migration:alembic')
        self.config.set_main_option("quiet_mode", "True")
        self.fileno, self.filepath = tempfile.mkstemp()
        secret_cfg = mock.MagicMock()
        secret_cfg.database.connection = "sqlite:///" + self.filepath
        self.config.neutron_config = secret_cfg

        self.engine = create_engine(
            self.config.neutron_config.database.connection,
            poolclass=pool.NullPool)
        self.connection = self.engine.connect()

    def tearDown(self):
        self.connection.close()
        os.unlink(self.filepath)


class Test2748e48cee3a(BaseMigrationTest):
    def setUp(self):
        super(Test2748e48cee3a, self).setUp()
        alembic_command.upgrade(self.config, '1284c81cf727')
        self.ip_policy_cidrs = table(
            'quark_ip_policy_cidrs',
            column('id', sa.String(length=36)),
            column('created_at', sa.DateTime()),
            column('ip_policy_id', sa.String(length=36)),
            column('cidr', sa.String(length=64)))
        self.subnets = table(
            'quark_subnets',
            column('id', sa.String(length=36)),
            column('_cidr', sa.String(length=64)),
            column('ip_policy_id', sa.String(length=36)))

    def test_upgrade_no_ip_policy_cidr(self):
        self.connection.execute(
            self.subnets.insert(),
            dict(id="000", _cidr="192.168.10.0/24", ip_policy_id=None))

        alembic_command.upgrade(self.config, '2748e48cee3a')
        results = self.connection.execute(
            select([self.ip_policy_cidrs])).fetchall()
        self.assertEqual(len(results), 0)

    def test_upgrade_ip_policy_cidr_inside(self):
        self.connection.execute(
            self.subnets.insert(),
            dict(id="000", _cidr="192.168.10.0/24", ip_policy_id="111"))
        dt = datetime.datetime(1970, 1, 1)
        self.connection.execute(
            self.ip_policy_cidrs.insert(),
            dict(id="222", created_at=dt,
                 ip_policy_id="111", cidr="192.168.10.0/32"))

        alembic_command.upgrade(self.config, '2748e48cee3a')
        results = self.connection.execute(
            select([self.ip_policy_cidrs])).fetchall()
        self.assertEqual(len(results), 1)
        result = results[0]
        self.assertEqual(result["id"], "222")
        self.assertEqual(result["created_at"], dt)
        self.assertEqual(result["ip_policy_id"], "111")
        self.assertEqual(result["cidr"], "192.168.10.0/32")

    def test_upgrade_ip_policy_cidr_overlaps(self):
        self.connection.execute(
            self.subnets.insert(),
            dict(id="000", _cidr="192.168.10.0/24", ip_policy_id="111"))
        self.connection.execute(
            self.ip_policy_cidrs.insert(),
            dict(id="222", created_at=datetime.date(1970, 1, 1),
                 ip_policy_id="111", cidr="192.168.10.0/16"))

        with contextlib.nested(
            mock.patch("neutron.openstack.common.timeutils"),
            mock.patch("neutron.openstack.common.uuidutils")
        ) as (tu, uuid):
            tu.utcnow.return_value = datetime.datetime(2004, 2, 14)
            uuid.generate_uuid.return_value = "foo"
            alembic_command.upgrade(self.config, '2748e48cee3a')
            results = self.connection.execute(
                select([self.ip_policy_cidrs])).fetchall()
            self.assertEqual(len(results), 1)
            result = results[0]
            self.assertEqual(result["id"], uuid.generate_uuid.return_value)
            self.assertEqual(result["created_at"], tu.utcnow.return_value)
            self.assertEqual(result["ip_policy_id"], "111")
            self.assertEqual(result["cidr"], "192.168.10.0/24")

    def test_upgrade_ip_policy_cidr_overlaps_v6(self):
        self.connection.execute(
            self.subnets.insert(),
            dict(id="000", _cidr="fd00::/8", ip_policy_id="111"))
        self.connection.execute(
            self.ip_policy_cidrs.insert(),
            dict(id="222", created_at=datetime.date(1970, 1, 1),
                 ip_policy_id="111", cidr="fd00::/7"))

        with contextlib.nested(
            mock.patch("neutron.openstack.common.timeutils"),
            mock.patch("neutron.openstack.common.uuidutils")
        ) as (tu, uuid):
            tu.utcnow.return_value = datetime.datetime(2004, 2, 14)
            uuid.generate_uuid.return_value = "foo"
            alembic_command.upgrade(self.config, '2748e48cee3a')
            results = self.connection.execute(
                select([self.ip_policy_cidrs])).fetchall()
            self.assertEqual(len(results), 1)
            result = results[0]
            self.assertEqual(result["id"], uuid.generate_uuid.return_value)
            self.assertEqual(result["created_at"], tu.utcnow.return_value)
            self.assertEqual(result["ip_policy_id"], "111")
            self.assertEqual(result["cidr"], "fd00::/8")

    def test_upgrade_ip_policy_cidr_outside(self):
        self.connection.execute(
            self.subnets.insert(),
            dict(id="000", _cidr="192.168.10.0/24", ip_policy_id="111"))
        self.connection.execute(
            self.ip_policy_cidrs.insert(),
            dict(id="222", created_at=datetime.date(1970, 1, 1),
                 ip_policy_id="111", cidr="0.0.0.0/24"))

        alembic_command.upgrade(self.config, '2748e48cee3a')
        results = self.connection.execute(
            select([self.ip_policy_cidrs])).fetchall()
        self.assertEqual(len(results), 0)

    def test_upgrade_bulk(self):
        self.connection.execute(
            self.subnets.insert(),
            dict(id="000", _cidr="192.168.10.0/24", ip_policy_id=None),
            dict(id="001", _cidr="192.168.10.0/24", ip_policy_id="111"),
            dict(id="002", _cidr="192.168.10.0/24", ip_policy_id="112"),
            dict(id="003", _cidr="192.168.10.0/24", ip_policy_id="113"))
        dt = datetime.datetime(1970, 1, 1)
        self.connection.execute(
            self.ip_policy_cidrs.insert(),
            dict(id="221", created_at=dt, ip_policy_id="111",
                 cidr="192.168.10.0/32"),
            dict(id="222", created_at=dt, ip_policy_id="112",
                 cidr="192.168.10.0/16"),
            dict(id="223", created_at=dt, ip_policy_id="113",
                 cidr="0.0.0.0/24"))

        with contextlib.nested(
            mock.patch("neutron.openstack.common.timeutils"),
            mock.patch("neutron.openstack.common.uuidutils")
        ) as (tu, uuid):
            tu.utcnow.return_value = datetime.datetime(2004, 2, 14)
            uuid.generate_uuid.return_value = "foo"
            alembic_command.upgrade(self.config, '2748e48cee3a')
            results = self.connection.execute(
                select([self.ip_policy_cidrs])).fetchall()
            self.assertEqual(len(results), 2)
            result = results[0] if results[0]["id"] == "foo" else results[1]
            self.assertEqual(result["id"], uuid.generate_uuid.return_value)
            self.assertEqual(result["created_at"], tu.utcnow.return_value)
            self.assertEqual(result["ip_policy_id"], "112")
            self.assertEqual(result["cidr"], "192.168.10.0/24")
            result = results[0] if results[0]["id"] != "foo" else results[1]
            self.assertEqual(result["id"], "221")
            self.assertEqual(result["created_at"], dt)
            self.assertEqual(result["ip_policy_id"], "111")
            self.assertEqual(result["cidr"], "192.168.10.0/32")

    def test_upgrade_multiple_ip_policy_cidrs(self):
        self.connection.execute(
            self.subnets.insert(),
            dict(id="000", _cidr="192.168.10.0/24", ip_policy_id="111"))
        self.connection.execute(
            self.ip_policy_cidrs.insert(),
            dict(id="221", created_at=datetime.date(1970, 1, 1),
                 ip_policy_id="111", cidr="0.0.0.0/24"),
            dict(id="222", created_at=datetime.date(1970, 1, 1),
                 ip_policy_id="111", cidr="192.168.10.255/32"),
            dict(id="223", created_at=datetime.date(1970, 1, 1),
                 ip_policy_id="111", cidr="192.168.10.0/23"))

        with contextlib.nested(
            mock.patch("neutron.openstack.common.timeutils"),
            mock.patch("neutron.openstack.common.uuidutils")
        ) as (tu, uuid):
            tu.utcnow.return_value = datetime.datetime(2004, 2, 14)
            uuid.generate_uuid.return_value = "foo"
            alembic_command.upgrade(self.config, '2748e48cee3a')
            results = self.connection.execute(
                select([self.ip_policy_cidrs])).fetchall()
            self.assertEqual(len(results), 1)
            result = results[0]
            self.assertEqual(result["id"], uuid.generate_uuid.return_value)
            self.assertEqual(result["created_at"], tu.utcnow.return_value)
            self.assertEqual(result["ip_policy_id"], "111")
            self.assertEqual(result["cidr"], "192.168.10.0/24")

    def test_downgrade(self):
        alembic_command.upgrade(self.config, '2748e48cee3a')
        with self.assertRaises(NotImplementedError):
            alembic_command.downgrade(self.config, '1284c81cf727')


class Test45a07fac3d38(BaseMigrationTest):
    def setUp(self):
        super(Test45a07fac3d38, self).setUp()
        alembic_command.upgrade(self.config, '2748e48cee3a')
        self.ip_policy_cidrs = table(
            'quark_ip_policy_cidrs',
            column('id', sa.String(length=36)),
            column('created_at', sa.DateTime()),
            column('ip_policy_id', sa.String(length=36)),
            column('cidr', sa.String(length=64)))
        self.subnets = table(
            'quark_subnets',
            column('id', sa.String(length=36)),
            column('_cidr', sa.String(length=64)),
            column('ip_policy_id', sa.String(length=36)))

    def test_upgrade_no_subnets_no_ip_policy_cidrs(self):
        alembic_command.upgrade(self.config, '45a07fac3d38')
        results = self.connection.execute(
            select([self.ip_policy_cidrs])).fetchall()
        self.assertEqual(len(results), 0)

    def test_upgrade_with_subnets_no_ip_policy(self):
        self.connection.execute(
            self.subnets.insert(),
            dict(id="000", _cidr="192.168.10.0/24", ip_policy_id=None))
        alembic_command.upgrade(self.config, '45a07fac3d38')
        results = self.connection.execute(
            select([self.ip_policy_cidrs])).fetchall()
        self.assertEqual(len(results), 0)

    def test_upgrade_with_subnets_no_ip_policy_cidrs(self):
        self.connection.execute(
            self.subnets.insert(),
            dict(id="000", _cidr="192.168.10.0/24", ip_policy_id="111"))
        alembic_command.upgrade(self.config, '45a07fac3d38')
        results = self.connection.execute(
            select([self.ip_policy_cidrs])).fetchall()
        self.assertEqual(len(results), 2)
        default_cidrs = ["192.168.10.0/32", "192.168.10.255/32"]
        self.assertIn(results[0]["cidr"], default_cidrs)
        self.assertIn(results[1]["cidr"], default_cidrs)
        self.assertNotEqual(results[0]["cidr"], results[1]["cidr"])

    def test_upgrade_with_subnets_non_default_ip_policy_cidrs(self):
        self.connection.execute(
            self.subnets.insert(),
            dict(id="000", _cidr="192.168.10.0/24", ip_policy_id="111"))
        self.connection.execute(
            self.ip_policy_cidrs.insert(),
            dict(id="222", created_at=datetime.date(1970, 1, 1),
                 ip_policy_id="111", cidr="192.168.10.13/32"))
        with contextlib.nested(
            mock.patch("neutron.openstack.common.timeutils"),
            mock.patch("neutron.openstack.common.uuidutils")
        ) as (tu, uuid):
            uuid.generate_uuid.side_effect = (1, 2, 3)
            tu.utcnow.return_value = datetime.datetime(1970, 1, 1)
            alembic_command.upgrade(self.config, '45a07fac3d38')
            results = self.connection.execute(
                select([self.ip_policy_cidrs])).fetchall()
            self.assertEqual(len(results), 3)
            default_cidrs = ["192.168.10.0/32", "192.168.10.255/32",
                             "192.168.10.13/32"]
            for result in results:
                self.assertIn(result["cidr"], default_cidrs)
                self.assertGreaterEqual(int(result["id"]), 1)
                self.assertLessEqual(int(result["id"]), 3)
                self.assertEqual(result["created_at"], tu.utcnow.return_value)
            self.assertNotEqual(results[0]["cidr"], results[1]["cidr"])
            self.assertNotEqual(results[0]["cidr"], results[2]["cidr"])
            self.assertNotEqual(results[1]["cidr"], results[2]["cidr"])

    def test_upgrade_with_subnets_non_default_ip_policy_cidrs_v6(self):
        self.connection.execute(
            self.subnets.insert(),
            dict(id="000", _cidr="fd00::/64", ip_policy_id="111"))
        self.connection.execute(
            self.ip_policy_cidrs.insert(),
            dict(id="222", created_at=datetime.date(1970, 1, 1),
                 ip_policy_id="111", cidr="fd00::3/128"))
        with contextlib.nested(
            mock.patch("neutron.openstack.common.timeutils"),
            mock.patch("neutron.openstack.common.uuidutils")
        ) as (tu, uuid):
            uuid.generate_uuid.side_effect = (1, 2, 3)
            tu.utcnow.return_value = datetime.datetime(1970, 1, 1)
            alembic_command.upgrade(self.config, '45a07fac3d38')
            results = self.connection.execute(
                select([self.ip_policy_cidrs])).fetchall()
            self.assertEqual(len(results), 3)
            default_cidrs = ["fd00::/128", "fd00::3/128",
                             "fd00::ffff:ffff:ffff:ffff/128"]
            for result in results:
                self.assertIn(result["cidr"], default_cidrs)
                self.assertGreaterEqual(int(result["id"]), 1)
                self.assertLessEqual(int(result["id"]), 3)
                self.assertEqual(result["created_at"], tu.utcnow.return_value)
            self.assertNotEqual(results[0]["cidr"], results[1]["cidr"])
            self.assertNotEqual(results[0]["cidr"], results[2]["cidr"])
            self.assertNotEqual(results[1]["cidr"], results[2]["cidr"])

    def test_upgrade_with_subnets_default_ip_policy_cidrs(self):
        self.connection.execute(
            self.subnets.insert(),
            dict(id="000", _cidr="192.168.10.0/24", ip_policy_id="111"))
        dt = datetime.datetime(1970, 1, 1)
        self.connection.execute(
            self.ip_policy_cidrs.insert(),
            dict(id="222", created_at=dt,
                 ip_policy_id="111", cidr="192.168.10.0/32"),
            dict(id="223", created_at=dt,
                 ip_policy_id="111", cidr="192.168.10.255/32"))
        alembic_command.upgrade(self.config, '45a07fac3d38')
        results = self.connection.execute(
            select([self.ip_policy_cidrs])).fetchall()
        self.assertEqual(len(results), 2)
        default_cidrs = ["192.168.10.0/32", "192.168.10.255/32"]
        self.assertIn(results[0]["cidr"], default_cidrs)
        self.assertIn(results[1]["cidr"], default_cidrs)
        self.assertTrue(results[0]["id"] == "222" or results[0]["id"] == "223")
        self.assertTrue(results[1]["id"] == "222" or results[1]["id"] == "223")
        self.assertEqual(results[0]["created_at"], dt)
        self.assertEqual(results[1]["created_at"], dt)

    def test_upgrade_bulk(self):
        self.connection.execute(
            self.subnets.insert(),
            dict(id="000", _cidr="192.168.10.0/24", ip_policy_id=None),
            dict(id="001", _cidr="192.168.10.0/24", ip_policy_id="111"),
            dict(id="002", _cidr="192.168.10.0/24", ip_policy_id="112"),
            dict(id="003", _cidr="192.168.10.0/24", ip_policy_id="113"))
        dt = datetime.datetime(1970, 1, 1)
        self.connection.execute(
            self.ip_policy_cidrs.insert(),
            dict(id="221", created_at=dt,
                 ip_policy_id="112", cidr="192.168.10.13/32"),
            dict(id="222", created_at=dt,
                 ip_policy_id="113", cidr="192.168.10.0/32"),
            dict(id="223", created_at=dt,
                 ip_policy_id="113", cidr="192.168.10.255/32"))

        alembic_command.upgrade(self.config, '45a07fac3d38')

        results = self.connection.execute(
            select([self.ip_policy_cidrs]).where(
                self.ip_policy_cidrs.c.ip_policy_id == None)).fetchall()  # noqa
        self.assertEqual(len(results), 0)

        results = self.connection.execute(
            select([self.ip_policy_cidrs]).where(
                self.ip_policy_cidrs.c.ip_policy_id == "111")).fetchall()
        self.assertEqual(len(results), 2)
        default_cidrs = ["192.168.10.0/32", "192.168.10.255/32"]
        self.assertIn(results[0]["cidr"], default_cidrs)
        self.assertIn(results[1]["cidr"], default_cidrs)
        self.assertNotEqual(results[0]["cidr"], results[1]["cidr"])

        results = self.connection.execute(
            select([self.ip_policy_cidrs]).where(
                self.ip_policy_cidrs.c.ip_policy_id == "112")).fetchall()
        self.assertEqual(len(results), 3)
        default_cidrs = ["192.168.10.0/32", "192.168.10.255/32",
                         "192.168.10.13/32"]
        for result in results:
            self.assertIn(result["cidr"], default_cidrs)
        self.assertNotEqual(results[0]["cidr"], results[1]["cidr"])
        self.assertNotEqual(results[0]["cidr"], results[2]["cidr"])
        self.assertNotEqual(results[1]["cidr"], results[2]["cidr"])

        results = self.connection.execute(
            select([self.ip_policy_cidrs]).where(
                self.ip_policy_cidrs.c.ip_policy_id == "113")).fetchall()
        self.assertEqual(len(results), 2)
        default_cidrs = ["192.168.10.0/32", "192.168.10.255/32"]
        self.assertIn(results[0]["cidr"], default_cidrs)
        self.assertIn(results[1]["cidr"], default_cidrs)
        self.assertTrue(results[0]["id"] == "222" or results[0]["id"] == "223")
        self.assertTrue(results[1]["id"] == "222" or results[1]["id"] == "223")
        self.assertEqual(results[0]["created_at"], dt)
        self.assertEqual(results[1]["created_at"], dt)

    def test_downgrade(self):
        alembic_command.upgrade(self.config, '45a07fac3d38')
        with self.assertRaises(NotImplementedError):
            alembic_command.downgrade(self.config, '2748e48cee3a')


class Test552b213c2b8c(BaseMigrationTest):
    def setUp(self):
        super(Test552b213c2b8c, self).setUp()
        alembic_command.upgrade(self.config, '45a07fac3d38')
        self.ip_policy = table(
            'quark_ip_policy',
            column('id', sa.String(length=36)),
            column('tenant_id', sa.String(length=255)),
            column('created_at', sa.DateTime()))
        self.ip_policy_cidrs = table(
            'quark_ip_policy_cidrs',
            column('id', sa.String(length=36)),
            column('created_at', sa.DateTime()),
            column('ip_policy_id', sa.String(length=36)),
            column('cidr', sa.String(length=64)))
        self.subnets = table(
            'quark_subnets',
            column('id', sa.String(length=36)),
            column('tenant_id', sa.String(length=255)),
            column('_cidr', sa.String(length=64)),
            column('ip_policy_id', sa.String(length=36)))

    def test_upgrade_no_subnets(self):
        alembic_command.upgrade(self.config, '552b213c2b8c')
        results = self.connection.execute(
            select([self.ip_policy_cidrs])).fetchall()
        self.assertEqual(len(results), 0)

    def test_upgrade_subnets_with_ip_policy(self):
        dt = datetime.datetime(1970, 1, 1)
        self.connection.execute(
            self.subnets.insert(),
            dict(id="000", tenant_id="foo", _cidr="192.168.10.0/24",
                 ip_policy_id="111"))
        self.connection.execute(
            self.ip_policy.insert(),
            dict(id="111", tenant_id="foo", created_at=dt))
        self.connection.execute(
            self.ip_policy_cidrs.insert(),
            dict(id="221", created_at=dt,
                 ip_policy_id="111", cidr="192.168.10.13/32"))
        alembic_command.upgrade(self.config, '552b213c2b8c')
        results = self.connection.execute(
            select([self.ip_policy])).fetchall()
        self.assertEqual(len(results), 1)
        result = results[0]
        self.assertEqual(result["id"], "111")
        self.assertEqual(result["tenant_id"], "foo")
        self.assertEqual(result["created_at"], dt)
        results = self.connection.execute(
            select([self.ip_policy_cidrs])).fetchall()
        self.assertEqual(len(results), 1)
        result = results[0]
        self.assertEqual(result["id"], "221")
        self.assertEqual(result["created_at"], dt)
        self.assertEqual(result["ip_policy_id"], "111")
        self.assertEqual(result["cidr"], "192.168.10.13/32")
        results = self.connection.execute(
            select([self.subnets])).fetchall()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["ip_policy_id"], "111")

    def test_upgrade_subnets_no_ip_policy(self):
        self.connection.execute(
            self.subnets.insert(),
            dict(id="000", tenant_id="foo", _cidr="192.168.10.0/24",
                 ip_policy_id=None))
        with contextlib.nested(
            mock.patch("neutron.openstack.common.timeutils"),
            mock.patch("neutron.openstack.common.uuidutils")
        ) as (tu, uuid):
            dt = datetime.datetime(1970, 1, 1)
            tu.utcnow.return_value = dt
            uuid.generate_uuid.side_effect = ("666", "667", "668")
            alembic_command.upgrade(self.config, '552b213c2b8c')
        results = self.connection.execute(
            select([self.ip_policy])).fetchall()
        self.assertEqual(len(results), 1)
        result = results[0]
        self.assertEqual(result["id"], "666")
        self.assertEqual(result["tenant_id"], "foo")
        self.assertEqual(result["created_at"], dt)
        results = self.connection.execute(
            select([self.ip_policy_cidrs])).fetchall()
        self.assertEqual(len(results), 2)
        for result in results:
            self.assertIn(result["id"], ("667", "668"))
            self.assertEqual(result["created_at"], dt)
            self.assertEqual(result["ip_policy_id"], "666")
            self.assertIn(result["cidr"],
                          ("192.168.10.0/32", "192.168.10.255/32"))
        self.assertNotEqual(results[0]["cidr"], results[1]["cidr"])
        results = self.connection.execute(
            select([self.subnets])).fetchall()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["ip_policy_id"], "666")

    def test_upgrade_subnets_no_ip_policy_v6(self):
        self.connection.execute(
            self.subnets.insert(),
            dict(id="000", tenant_id="foo", _cidr="fd00::/64",
                 ip_policy_id=None))
        with contextlib.nested(
            mock.patch("neutron.openstack.common.timeutils"),
            mock.patch("neutron.openstack.common.uuidutils")
        ) as (tu, uuid):
            dt = datetime.datetime(1970, 1, 1)
            tu.utcnow.return_value = dt
            uuid.generate_uuid.side_effect = ("666", "667", "668")
            alembic_command.upgrade(self.config, '552b213c2b8c')
        results = self.connection.execute(
            select([self.ip_policy])).fetchall()
        self.assertEqual(len(results), 1)
        result = results[0]
        self.assertEqual(result["id"], "666")
        self.assertEqual(result["tenant_id"], "foo")
        self.assertEqual(result["created_at"], dt)
        results = self.connection.execute(
            select([self.ip_policy_cidrs])).fetchall()
        self.assertEqual(len(results), 2)
        for result in results:
            self.assertIn(result["id"], ("667", "668"))
            self.assertEqual(result["created_at"], dt)
            self.assertEqual(result["ip_policy_id"], "666")
            self.assertIn(result["cidr"],
                          ("fd00::/128",
                           "fd00::ffff:ffff:ffff:ffff/128"))
        self.assertNotEqual(results[0]["cidr"], results[1]["cidr"])
        results = self.connection.execute(
            select([self.subnets])).fetchall()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["ip_policy_id"], "666")

    def test_upgrade_bulk(self):
        dt = datetime.datetime(1970, 1, 1)
        self.connection.execute(
            self.subnets.insert(),
            dict(id="000", tenant_id="foo", _cidr="192.168.10.0/24",
                 ip_policy_id="111"),
            dict(id="001", tenant_id="foo", _cidr="192.168.10.0/24",
                 ip_policy_id=None),
            dict(id="002", tenant_id="foo", _cidr="fd00::/64",
                 ip_policy_id=None))
        self.connection.execute(
            self.ip_policy.insert(),
            dict(id="111", tenant_id="foo", created_at=dt))
        self.connection.execute(
            self.ip_policy_cidrs.insert(),
            dict(id="221", created_at=dt,
                 ip_policy_id="111", cidr="192.168.10.13/32"))

        with contextlib.nested(
            mock.patch("neutron.openstack.common.timeutils"),
            mock.patch("neutron.openstack.common.uuidutils")
        ) as (tu, uuid):
            tu.utcnow.return_value = dt
            uuid.generate_uuid.side_effect = ("5", "6", "7", "8", "9", "10")
            alembic_command.upgrade(self.config, '552b213c2b8c')

        results = self.connection.execute(
            select([self.ip_policy]).where(
                self.ip_policy.c.id == "111")).fetchall()
        self.assertEqual(len(results), 1)
        result = results[0]
        self.assertEqual(result["id"], "111")
        self.assertEqual(result["tenant_id"], "foo")
        self.assertEqual(result["created_at"], dt)
        results = self.connection.execute(
            select([self.ip_policy_cidrs]).where(
                self.ip_policy_cidrs.c.ip_policy_id == "111")).fetchall()
        self.assertEqual(len(results), 1)
        result = results[0]
        self.assertEqual(result["id"], "221")
        self.assertEqual(result["created_at"], dt)
        self.assertEqual(result["ip_policy_id"], "111")
        self.assertEqual(result["cidr"], "192.168.10.13/32")
        results = self.connection.execute(
            select([self.subnets]).where(
                self.subnets.c.ip_policy_id == "111")).fetchall()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["ip_policy_id"], "111")

        results = self.connection.execute(
            select([self.ip_policy]).where(
                self.ip_policy.c.id != "111")).fetchall()
        self.assertEqual(len(results), 2)
        for result in results:
            self.assertIn(int(result["id"]), range(5, 11))
            self.assertEqual(result["tenant_id"], "foo")
            self.assertEqual(result["created_at"], dt)
        results = self.connection.execute(
            select([self.ip_policy_cidrs]).where(
                self.ip_policy_cidrs.c.ip_policy_id != "111")).fetchall()
        self.assertEqual(len(results), 4)
        for result in results:
            self.assertIn(int(result["id"]), range(5, 11))
            self.assertEqual(result["created_at"], dt)
            self.assertIn(int(result["ip_policy_id"]), range(5, 11))
            self.assertIn(result["cidr"], (
                "192.168.10.0/32", "192.168.10.255/32",
                "fd00::/128", "fd00::ffff:ffff:ffff:ffff/128"))
        results = self.connection.execute(
            select([self.subnets]).where(
                self.subnets.c.ip_policy_id != "111")).fetchall()
        self.assertEqual(len(results), 2)
        for subnet in results:
            self.assertIn(int(subnet["ip_policy_id"]), range(5, 11))

    def test_downgrade(self):
        alembic_command.upgrade(self.config, '552b213c2b8c')
        with self.assertRaises(NotImplementedError):
            alembic_command.downgrade(self.config, '45a07fac3d38')


class Test28e55acaf366(BaseMigrationTest):
    def setUp(self):
        super(Test28e55acaf366, self).setUp()
        alembic_command.upgrade(self.config, '3d22de205729')
        self.ip_policy = table('quark_ip_policy',
                               column('id', sa.String(length=36)),
                               column('size', INET()))
        self.ip_policy_cidrs = table(
            'quark_ip_policy_cidrs',
            column('id', sa.String(length=36)),
            column('ip_policy_id', sa.String(length=36)),
            column('cidr', sa.String(length=64)))

    def test_upgrade_none(self):
        alembic_command.upgrade(self.config, '28e55acaf366')
        results = self.connection.execute(select([
            self.ip_policy])).fetchall()
        self.assertEqual(len(results), 0)
        results = self.connection.execute(select([
            self.ip_policy_cidrs])).fetchall()
        self.assertEqual(len(results), 0)

    def test_upgrade_v4(self):
        self.connection.execute(
            self.ip_policy.insert(), dict(id="1", size=None))
        self.connection.execute(
            self.ip_policy_cidrs.insert(),
            dict(id="2", ip_policy_id="1", cidr="192.168.10.13/32"),
            dict(id="3", ip_policy_id="1", cidr="192.168.10.16/31"))
        alembic_command.upgrade(self.config, '28e55acaf366')
        results = self.connection.execute(select([
            self.ip_policy])).fetchall()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["id"], "1")
        self.assertEqual(results[0]["size"], 3)

    def test_upgrade_v6(self):
        self.connection.execute(
            self.ip_policy.insert(), dict(id="1", size=None))
        self.connection.execute(
            self.ip_policy_cidrs.insert(),
            dict(id="2", ip_policy_id="1", cidr="fd00::/64"))
        alembic_command.upgrade(self.config, '28e55acaf366')
        results = self.connection.execute(select([
            self.ip_policy])).fetchall()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["id"], "1")
        self.assertEqual(results[0]["size"], 2 ** 64)

    def test_upgrade_bulk(self):
        self.connection.execute(
            self.ip_policy.insert(),
            dict(id="1", size=None),
            dict(id="2", size=None))
        self.connection.execute(
            self.ip_policy_cidrs.insert(),
            dict(id="2", ip_policy_id="1", cidr="192.168.10.13/32"),
            dict(id="3", ip_policy_id="1", cidr="192.168.10.16/31"),
            dict(id="4", ip_policy_id="2", cidr="fd00::/64"))
        alembic_command.upgrade(self.config, '28e55acaf366')
        results = self.connection.execute(select([
            self.ip_policy])).fetchall()
        self.assertEqual(len(results), 2)
        for result in results:
            self.assertIn(result["id"], ("1", "2"))
            if result["id"] == "1":
                self.assertEqual(result["size"], 3)
            elif result["id"] == "2":
                self.assertEqual(result["size"], 2 ** 64)

    def test_downgrade(self):
        alembic_command.upgrade(self.config, '28e55acaf366')
        with self.assertRaises(NotImplementedError):
            alembic_command.downgrade(self.config, '3d22de205729')


class Test1664300cb03a(BaseMigrationTest):
    def setUp(self):
        super(Test1664300cb03a, self).setUp()
        alembic_command.upgrade(self.config, '1acd075bd7e1')
        self.ip_policy_cidrs = table(
            'quark_ip_policy_cidrs',
            column('id', sa.String(length=36)),
            column('ip_policy_id', sa.String(length=36)),
            column('cidr', sa.String(length=64)),
            column('first_ip', INET()),
            column('last_ip', INET()))

    def test_upgrade_empty(self):
        alembic_command.upgrade(self.config, '1664300cb03a')
        results = self.connection.execute(select([
            self.ip_policy_cidrs])).fetchall()
        self.assertEqual(len(results), 0)

    def test_upgrade_ipv4(self):
        net = netaddr.IPNetwork("192.168.10.13/31")
        self.connection.execute(
            self.ip_policy_cidrs.insert(),
            dict(id="1", ip_policy_id="1", cidr=str(net)))
        alembic_command.upgrade(self.config, '1664300cb03a')
        results = self.connection.execute(select([
            self.ip_policy_cidrs])).fetchall()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["id"], "1")
        self.assertEqual(results[0]["ip_policy_id"], "1")
        self.assertEqual(results[0]["cidr"], str(net))
        self.assertEqual(results[0]["first_ip"], net.ipv6().first)
        self.assertEqual(results[0]["last_ip"], net.ipv6().last)

    def test_upgrade_ipv6(self):
        net = netaddr.IPNetwork("fd00::/64")
        self.connection.execute(
            self.ip_policy_cidrs.insert(),
            dict(id="1", ip_policy_id="1", cidr=str(net)))
        alembic_command.upgrade(self.config, '1664300cb03a')
        results = self.connection.execute(select([
            self.ip_policy_cidrs])).fetchall()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["id"], "1")
        self.assertEqual(results[0]["ip_policy_id"], "1")
        self.assertEqual(results[0]["cidr"], "fd00::/64")
        self.assertEqual(results[0]["first_ip"], net.first)
        self.assertEqual(results[0]["last_ip"], net.last)

    def test_upgrade_bulk(self):
        netv4 = netaddr.IPNetwork("192.168.10.13/31")
        netv6 = netaddr.IPNetwork("fd00::/64")
        self.connection.execute(
            self.ip_policy_cidrs.insert(),
            dict(id="1", ip_policy_id="1", cidr=str(netv4)),
            dict(id="2", ip_policy_id="2", cidr=str(netv6)))
        alembic_command.upgrade(self.config, '1664300cb03a')
        results = self.connection.execute(select([
            self.ip_policy_cidrs])).fetchall()
        self.assertEqual(len(results), 2)
        for result in results:
            self.assertIn(result["cidr"], (str(netv4), str(netv6)))
            if result["cidr"] == "192.168.10.13/31":
                self.assertEqual(result["first_ip"], netv4.ipv6().first)
                self.assertEqual(result["last_ip"], netv4.ipv6().last)
            else:
                self.assertEqual(result["first_ip"], netv6.first)
                self.assertEqual(result["last_ip"], netv6.last)

    def test_downgrade(self):
        alembic_command.upgrade(self.config, '1664300cb03a')
        with self.assertRaises(NotImplementedError):
            alembic_command.downgrade(self.config, '1acd075bd7e1')
