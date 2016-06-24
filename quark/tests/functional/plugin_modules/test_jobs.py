# Copyright 2016 Rackspace Hosting Inc
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for# the specific language governing permissions and limitations
#  under the License.
from oslo_log import log as logging

from neutron_lib import exceptions as n_exc

from quark import exceptions as q_exc
from quark.plugin_modules import jobs as job_api
from quark.tests.functional.base import BaseFunctionalTest

LOG = logging.getLogger(__name__)


class QuarkJobs(BaseFunctionalTest):
    def setUp(self):
        super(QuarkJobs, self).setUp()
        self.action = "test action"
        self.tenant_id = "test_tenant"
        self.tenant_id2 = "test_tenant2"

    def test_create_job(self):
        job_body = dict(tenant_id=self.tenant_id, action=self.action,
                        completed=False)
        job_body = dict(job=job_body)
        job = job_api.create_job(self.admin_context, job_body)
        self.assertIsNotNone(job)
        self.assertFalse(job['completed'])
        self.assertEqual(self.tenant_id, job['tenant_id'])
        self.assertEqual(self.action, job['action'])
        self.assertEqual(None, job['parent_id'])
        self.assertEqual(job['id'], job['transaction_id'])

    def test_create_job_with_parent_job(self):
        job_body = dict(tenant_id=self.tenant_id, action=self.action,
                        completed=False)
        job_body = dict(job=job_body)
        parent_job = job_api.create_job(self.admin_context, job_body)
        job_body = dict(tenant_id=self.tenant_id, action=self.action,
                        completed=False, parent_id=parent_job['id'])
        job_body = dict(job=job_body)
        job = job_api.create_job(self.admin_context, job_body)
        self.assertIsNotNone(job)
        self.assertFalse(job['completed'])
        self.assertEqual(self.tenant_id, job['tenant_id'])
        self.assertEqual(self.action, job['action'])
        self.assertEqual(parent_job['id'], job['parent_id'])
        self.assertEqual(parent_job['id'], job['transaction_id'],
                         "transaction id should be outer most parent id")

    def test_create_deep_job_list(self):
        parent_job = None
        transaction = None
        for i in xrange(4):
            job_body = dict(tenant_id=self.tenant_id, action=self.action,
                            completed=False)
            if parent_job:
                job_body['parent_id'] = parent_job
            job_body = dict(job=job_body)
            job = job_api.create_job(self.admin_context, job_body)
            self.assertIsNotNone(job)
            if parent_job:
                self.assertEqual(parent_job, job['parent_id'])
            if transaction is None:
                self.assertIsNotNone(job['transaction_id'])
                transaction = job['id']
            else:
                self.assertEqual(transaction, job['transaction_id'])
            parent_job = job['id']

    def test_create_job_fail_non_admin(self):
        job_body = dict(tenant_id=self.tenant_id, action=self.action,
                        completed=False)
        job_body = dict(job=job_body)
        with self.assertRaises(n_exc.NotAuthorized):
            job_api.create_job(self.context, job_body)

    def test_get_jobs(self):
        job_body = dict(tenant_id=self.tenant_id, action=self.action,
                        completed=False, resource_id='foo')
        job_body = dict(job=job_body)
        job1 = job_api.create_job(self.admin_context, job_body)
        self.assertIsNotNone(job1)

        job_body = dict(tenant_id=self.tenant_id2, action=self.action,
                        completed=True, resource_id='bar')
        job_body = dict(job=job_body)
        job2 = job_api.create_job(self.admin_context, job_body)
        self.assertIsNotNone(job2)

        jobs = job_api.get_job(self.admin_context, job1['id'])
        self.assertFalse(type(jobs) in [list, tuple])
        job = jobs
        self.assertFalse(job['completed'])
        self.assertEqual(self.tenant_id, job['tenant_id'])
        self.assertEqual(self.action, job['action'])

        job = job_api.get_job(self.admin_context, job2['id'])
        self.assertTrue(job['completed'])
        self.assertEqual(self.tenant_id2, job['tenant_id'])
        self.assertEqual(self.action, job['action'])

        with self.assertRaises(q_exc.JobNotFound):
            job_api.get_job(self.admin_context, 'derp')

        jobs = job_api.get_jobs(self.admin_context)
        self.assertTrue(type(jobs) in [list, tuple])
        self.assertEqual(2, len(jobs))

        jobs = job_api.get_jobs(self.admin_context, completed=True)
        self.assertTrue(type(jobs) in [list, tuple])
        self.assertEqual(1, len(jobs))

        jobs = job_api.get_jobs(self.admin_context, completed=False)
        self.assertTrue(type(jobs) in [list, tuple])
        self.assertEqual(1, len(jobs))

        jobs = job_api.get_jobs(self.admin_context, completed='hello')
        self.assertTrue(type(jobs) in [list, tuple])
        self.assertEqual(0, len(jobs))

        jobs = job_api.get_jobs(self.admin_context, tenant_id=self.tenant_id)
        self.assertTrue(type(jobs) in [list, tuple])
        self.assertEqual(1, len(jobs))

        jobs = job_api.get_jobs(self.admin_context, tenant_id='derp')
        self.assertTrue(type(jobs) in [list, tuple])
        self.assertEqual(0, len(jobs))

        jobs = job_api.get_jobs(self.admin_context, resource_id='foo')
        self.assertTrue(type(jobs) in [list, tuple])
        self.assertEqual(1, len(jobs))

        jobs = job_api.get_jobs(self.admin_context, resource_id='bar')
        self.assertTrue(type(jobs) in [list, tuple])
        self.assertEqual(1, len(jobs))

        jobs = job_api.get_jobs(self.admin_context, resource_id='asdf')
        self.assertTrue(type(jobs) in [list, tuple])
        self.assertEqual(0, len(jobs))

    def test_get_job_different_non_admin(self):
        job_body = dict(tenant_id=self.context.tenant_id, action=self.action,
                        completed=False)
        job_body = dict(job=job_body)
        job1 = job_api.create_job(self.admin_context, job_body)
        self.assertIsNotNone(job1)

        job_body = dict(tenant_id=self.tenant_id2, action=self.action,
                        completed=True)
        job_body = dict(job=job_body)
        job2 = job_api.create_job(self.admin_context, job_body)
        self.assertIsNotNone(job2)

        jobs = job_api.get_jobs(self.context)
        self.assertTrue(type(jobs) in [list, tuple])

        self.assertEqual(1, len(jobs))
        self.assertEqual(self.context.tenant_id, jobs[0]['tenant_id'])

    def test_update_jobs(self):
        update_body = dict(completed=True)
        update_body = dict(job=update_body)

        with self.assertRaises(q_exc.JobNotFound):
            job_api.update_job(self.admin_context, 'derp', update_body)

        job_body = dict(tenant_id=self.tenant_id, action=self.action,
                        completed=False)
        job_body = dict(job=job_body)
        job1 = job_api.create_job(self.admin_context, job_body)
        self.assertIsNotNone(job1)

        job = job_api.get_job(self.admin_context, job1['id'])
        self.assertFalse(job['completed'])

        updated_job = job_api.update_job(self.admin_context, job1['id'],
                                         update_body)
        self.assertTrue(updated_job['completed'])

        job = job_api.get_job(self.admin_context, job1['id'])
        self.assertTrue(job['completed'])

    def test_update_job_fail_non_admin(self):
        update_body = dict(completed=True)
        update_body = dict(job=update_body)

        job_body = dict(tenant_id=self.tenant_id, action=self.action,
                        completed=False)
        job_body = dict(job=job_body)
        job1 = job_api.create_job(self.admin_context, job_body)
        self.assertIsNotNone(job1)

        job = job_api.get_job(self.admin_context, job1['id'])
        self.assertFalse(job['completed'])

        with self.assertRaises(n_exc.NotAuthorized):
            job_api.update_job(self.context, job1['id'], update_body)

        updated_job = job_api.update_job(self.admin_context, job1['id'],
                                         update_body)
        self.assertTrue(updated_job['completed'])

        job = job_api.get_job(self.admin_context, job1['id'])
        self.assertTrue(job['completed'])

    def test_delete_jobs(self):
        with self.assertRaises(q_exc.JobNotFound):
            job_api.delete_job(self.admin_context, 'derp')

        job_body = dict(tenant_id=self.tenant_id, action=self.action,
                        completed=False)
        job_body = dict(job=job_body)
        job1 = job_api.create_job(self.admin_context, job_body)
        self.assertIsNotNone(job1)

        job = job_api.get_job(self.admin_context, job1['id'])
        self.assertFalse(job['completed'])

        job_api.delete_job(self.admin_context, job1['id'])

        with self.assertRaises(q_exc.JobNotFound):
            job_api.get_job(self.admin_context, job1['id'])

        with self.assertRaises(q_exc.JobNotFound):
            job_api.delete_job(self.admin_context, job1['id'])

    def test_delete_job_with_children(self):
        job_body = dict(tenant_id=self.tenant_id, action=self.action,
                        completed=False)
        job_body = dict(job=job_body)
        parent_job = job_api.create_job(self.admin_context, job_body)
        parent_job = job_api.get_job(self.admin_context, parent_job['id'])
        self.assertIsNotNone(parent_job)
        job_body = dict(tenant_id=self.tenant_id, action=self.action,
                        completed=False, parent_id=parent_job['id'])
        job_body = dict(job=job_body)
        job = job_api.create_job(self.admin_context, job_body)
        job = job_api.get_job(self.admin_context, job['id'])
        self.assertIsNotNone(job)

        job_body = dict(tenant_id=self.tenant_id, action=self.action,
                        completed=False, parent_id=job['id'])
        job_body = dict(job=job_body)
        subjob = job_api.create_job(self.admin_context, job_body)
        subjob = job_api.get_job(self.admin_context, subjob['id'])
        self.assertIsNotNone(job)

        job_api.delete_job(self.admin_context, parent_job['id'])

        with self.assertRaises(q_exc.JobNotFound):
            job_api.get_job(self.admin_context, parent_job['id'])

        with self.assertRaises(q_exc.JobNotFound):
            job_api.get_job(self.admin_context, job['id'])

        with self.assertRaises(q_exc.JobNotFound):
            job_api.get_job(self.admin_context, subjob['id'])

    def test_delete_job_fail_non_admin(self):
        with self.assertRaises(n_exc.NotAuthorized):
            job_api.delete_job(self.context, 'derp')

        job_body = dict(tenant_id=self.tenant_id, action=self.action,
                        completed=False)
        job_body = dict(job=job_body)
        job1 = job_api.create_job(self.admin_context, job_body)
        self.assertIsNotNone(job1)

        job = job_api.get_job(self.admin_context, job1['id'])
        self.assertFalse(job['completed'])

        with self.assertRaises(n_exc.NotAuthorized):
            job_api.delete_job(self.context, job1['id'])

        job_api.delete_job(self.admin_context, job1['id'])

        with self.assertRaises(q_exc.JobNotFound):
            job_api.get_job(self.context, job1['id'])

    def test_transaction_completion_percent(self):
        job_body = dict(tenant_id=self.tenant_id, action=self.action,
                        completed=False)
        job_body = dict(job=job_body)
        parent_job = job_api.create_job(self.admin_context, job_body)
        parent_job = job_api.get_job(self.admin_context, parent_job['id'])
        self.assertIsNotNone(parent_job)
        job_body = dict(tenant_id=self.tenant_id, action=self.action,
                        completed=False, parent_id=parent_job['id'])
        job_body = dict(job=job_body)
        job = job_api.create_job(self.admin_context, job_body)
        job = job_api.get_job(self.admin_context, job['id'])
        self.assertIsNotNone(job)

        job_body = dict(tenant_id=self.tenant_id, action=self.action,
                        completed=False, parent_id=job['id'])
        job_body = dict(job=job_body)
        subjob = job_api.create_job(self.admin_context, job_body)
        subjob = job_api.get_job(self.admin_context, subjob['id'])
        self.assertIsNotNone(job)

        parent_job = job_api.get_job(self.admin_context, parent_job['id'])
        self.assertTrue('transaction_percent' in parent_job)
        self.assertEqual(0, parent_job['transaction_percent'])

        update_body = dict(completed=True)
        update_body = dict(job=update_body)

        subjob = job_api.update_job(self.admin_context, subjob['id'],
                                    update_body)
        self.assertTrue(subjob['completed'])

        parent_job = job_api.get_job(self.admin_context, parent_job['id'])
        self.assertEqual(50, parent_job['transaction_percent'])

        job = job_api.update_job(self.admin_context, job['id'], update_body)
        self.assertTrue(subjob['completed'])

        parent_job = job_api.get_job(self.admin_context, parent_job['id'])
        self.assertEqual(100, parent_job['transaction_percent'])
        self.assertEqual(True, parent_job['completed'])
