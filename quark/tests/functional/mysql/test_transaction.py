from quark.db import api as quark_db_api
from quark.tests.functional.mysql.base import MySqlBaseFunctionalTest


class QuarkTransactionFunctionalTest(MySqlBaseFunctionalTest):
    def test_transaction_id(self):
        with self.context.session.begin():
            transaction = quark_db_api.transaction_create(self.context)
        self.assertEqual(1, transaction.id)
        with self.context.session.begin():
            transaction = quark_db_api.transaction_create(self.context)
        self.assertEqual(2, transaction.id)
        with self.context.session.begin():
            transaction = quark_db_api.transaction_create(self.context)
        self.assertEqual(3, transaction.id)
