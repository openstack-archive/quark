from quark.db import models
from quark.db import sqlalchemy_adapter as quark_sa
from quark.tests.functional.mysql.base import MySqlBaseFunctionalTest


class QuarkSqlAlchemyFunctionalTest(MySqlBaseFunctionalTest):
    def test_mysql_limit_1(self):
        notfoobar = "notfoobar"
        ip1 = models.IPAddress(address=0, address_readable="0",
                               used_by_tenant_id=notfoobar)
        ip2 = models.IPAddress(address=1, address_readable="1",
                               used_by_tenant_id=notfoobar)
        self.context.session.add(ip1)
        self.context.session.add(ip2)
        self.context.session.flush()

        query = self.context.session.query(models.IPAddress)
        row_count = quark_sa.update(query,
                                    dict(used_by_tenant_id="foobar"),
                                    update_args={"mysql_limit": 1})
        self.assertEqual(row_count, 1)

        self.context.session.refresh(ip1)
        self.context.session.refresh(ip2)
        self.assertEqual(sum((ip1["used_by_tenant_id"] == notfoobar,
                              ip2["used_by_tenant_id"] == notfoobar)),
                         1)
