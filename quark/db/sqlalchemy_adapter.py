from sqlalchemy.orm.persistence import BulkUpdate
from sqlalchemy import sql


# NOTE(asadoughi): based on https://github.com/zzzeek/sqlalchemy/pull/164
class BulkUpdateArgs(BulkUpdate):
    def __init__(self, query, values, update_kwargs):
        super(BulkUpdateArgs, self).__init__(query, values)
        self.update_kwargs = update_kwargs

    def _do_exec(self):
        update_stmt = sql.update(self.primary_table,
                                 whereclause=self.context.whereclause,
                                 values=self.values,
                                 **self.update_kwargs)
        self.result = self.query.session.execute(
            update_stmt, params=self.query._params)
        self.rowcount = self.result.rowcount


def update(query, values, update_args=None):
    update_args = update_args or {}
    update_op = BulkUpdateArgs(query, values, update_args)
    update_op.exec_()
    return update_op.rowcount
