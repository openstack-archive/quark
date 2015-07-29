from quark.db import models
from quark.drivers import optimized_nvp_driver  # noqa
from quark import quota_driver


# add your model's MetaData object here
# for 'autogenerate' support
target_metadata = models.BASEV2.metadata
# FIXME: https://bitbucket.org/zzzeek/alembic/issue/38
table_names = set([tbl.name for tbl in target_metadata.sorted_tables])
for t in quota_driver.Quota.metadata.tables.values():
    if t.name == "quotas" and t.name not in table_names:
        t.tometadata(target_metadata)
