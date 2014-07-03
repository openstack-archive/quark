import contextlib
import datetime
import os
import tempfile

from alembic import command as alembic_command
from alembic import config as alembic_config
import mock
import sqlalchemy as sa
from sqlalchemy import create_engine
from sqlalchemy import pool
from sqlalchemy.sql import column
from sqlalchemy.sql import select
from sqlalchemy.sql import table

import quark.db.migration
from quark.tests import test_base


class BaseMigrationTest(test_base.TestBase):
    def setUp(self):
        self.config = alembic_config.Config(
            os.path.join(quark.db.migration.__path__[0], 'alembic.ini'))
        self.config.set_main_option('script_location',
                                    'quark.db.migration:alembic')
        self.fileno, self.filepath = tempfile.mkstemp()
        secret_cfg = mock.MagicMock()
        secret_cfg.database.connection = "sqlite:///" + self.filepath
        self.config.neutron_config = secret_cfg

        engine = create_engine(
            self.config.neutron_config.database.connection,
            poolclass=pool.NullPool)
        self.connection = engine.connect()

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
