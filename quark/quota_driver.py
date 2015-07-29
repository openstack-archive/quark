# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011 OpenStack Foundation.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from neutron.db.quota.models import Quota
from neutron.db import quota_db


class QuarkQuotaDriver(quota_db.DbQuotaDriver):
    """Driver to perform necessary checks to enforce and obtain quotas.

    The default driver utilizes the local database.
    """

    @staticmethod
    def delete_tenant_quota(context, tenant_id):
        """Delete the quota entries for a given tenant_id.

        Atfer deletion, this tenant will use default quota values in conf.
        """

        tenant_quotas = context.session.query(Quota)
        tenant_quotas = tenant_quotas.filter_by(tenant_id=tenant_id)
        tenant_quotas.delete()

    @staticmethod
    def update_quota_limit(context, tenant_id, resource, limit):
        tenant_quota = context.session.query(Quota).filter_by(
            tenant_id=tenant_id, resource=resource).first()

        if tenant_quota:
            tenant_quota.update({'limit': limit})
        else:
            tenant_quota = Quota(tenant_id=tenant_id,
                                 resource=resource,
                                 limit=limit)
            context.session.add(tenant_quota)
