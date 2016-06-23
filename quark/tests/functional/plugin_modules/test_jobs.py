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

    def test_create_job_fail_non_admin(self):
        job_body = dict(tenant_id=self.tenant_id, action=self.action,
                        completed=False)
        job_body = dict(job=job_body)
        with self.assertRaises(n_exc.NotAuthorized):
            job_api.create_job(self.context, job_body)

    def test_get_jobs(self):
        job_body = dict(tenant_id=self.tenant_id, action=self.action,
                        completed=False)
        job_body = dict(job=job_body)
        job1 = job_api.create_job(self.admin_context, job_body)
        self.assertIsNotNone(job1)

        job_body = dict(tenant_id=self.tenant_id2, action=self.action,
                        completed=True)
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
