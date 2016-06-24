# Copyright (c) 2016 Rackspace Hosting Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import contextlib
import json
import mock

from quark.tests import test_base
from quark.tools.middleware import resp_async_id as jobmw


mw_mock_path = 'quark.tools.middleware.resp_async_id.ResponseAsyncIdAdder'


class FakeResp(object):
    def __init__(self, body):
        self.body = body
        self.headers = {}


class FakeContext(object):
    def __init__(self, job):
        self.async_job = job


class TestRespAsyncIDMiddleware(test_base.TestBase):
    def setUp(self):
        self.middleware_cls = jobmw.ResponseAsyncIdAdder
        self.app = mock.Mock()
        self.conf = {}
        job = {'job': {'id': '3'}}
        self.job_ctx = FakeContext(job)
        self.no_ctx = {}
        self.none_ctx = None
        self.random_ctx = {'stuff': {'stuff': 'value'}}

        self.body = '{"something": {"attribute": "value"}}'
        self.resp_return = FakeResp(self.body)
        self.err_resp = FakeResp('asdf::')

    def test_middleware_instantiation(self):
        self.assertIsNotNone(self.middleware_cls(self.app, self.conf))

        mw = jobmw.filter_factory(self.conf)(self.app)
        self.assertIsNotNone(mw)

    def test_mw_none_context(self):
        mw = jobmw.filter_factory(self.conf)(self.app)
        with contextlib.nested(
                mock.patch('%s._get_resp' % mw_mock_path),
                mock.patch('%s._get_ctx' % mw_mock_path)) as \
                (get_resp, get_ctx):
            get_resp.return_value = self.resp_return
            get_ctx.return_value = self.none_ctx
            resp = mw.__call__.request('/', method='GET', body=self.body)
            self.assertEqual(resp, self.resp_return)
            self.assertEqual(self.body, resp.body)
            self.assertFalse('job_id' in resp.body)
            self.assertFalse('job_id' in resp.headers)

    def test_mw_empty_context(self):
        mw = jobmw.filter_factory(self.conf)(self.app)
        with contextlib.nested(
                mock.patch('%s._get_resp' % mw_mock_path),
                mock.patch('%s._get_ctx' % mw_mock_path)) as \
                (get_resp, get_ctx):
            get_resp.return_value = self.resp_return
            get_ctx.return_value = self.no_ctx
            resp = mw.__call__.request('/', method='GET', body=self.body)
            self.assertEqual(resp, self.resp_return)
            self.assertEqual(self.body, resp.body)
            self.assertFalse('job_id' in resp.body)
            self.assertFalse('job_id' in resp.headers)

    def test_mw_missing_context(self):
        mw = jobmw.filter_factory(self.conf)(self.app)
        with contextlib.nested(
                mock.patch('%s._get_resp' % mw_mock_path),
                mock.patch('%s._get_ctx' % mw_mock_path)) as \
                (get_resp, get_ctx):
            get_resp.return_value = self.resp_return
            get_ctx.return_value = self.random_ctx
            resp = mw.__call__.request('/', method='GET', body=self.body)
            self.assertEqual(resp, self.resp_return)
            self.assertEqual(self.body, resp.body)
            self.assertFalse('job_id' in resp.body)
            self.assertFalse('job_id' in resp.headers)

    def test_mw_modify_resp(self):
        mw = jobmw.filter_factory(self.conf)(self.app)
        with contextlib.nested(
                mock.patch('%s._get_resp' % mw_mock_path),
                mock.patch('%s._get_ctx' % mw_mock_path)) as \
                (get_resp, get_ctx):
            get_resp.return_value = self.resp_return
            get_ctx.return_value = self.job_ctx
            resp = mw.__call__.request('/', method='GET', body=self.body)
            self.assertEqual(resp, self.resp_return)
            self.assertNotEqual(self.body, resp.body)
            self.assertTrue('job_id' in resp.body)
            self.assertTrue('job_id' in resp.headers)

            resp_json = json.loads(resp.body)
            self.assertTrue('job_id' in resp_json)

    def test_mw_error_resp(self):
        mw = jobmw.filter_factory(self.conf)(self.app)
        with contextlib.nested(
                mock.patch('%s._get_resp' % mw_mock_path),
                mock.patch('%s._get_ctx' % mw_mock_path)) as \
                (get_resp, get_ctx):
            get_resp.return_value = self.err_resp
            get_ctx.return_value = self.job_ctx
            resp = mw.__call__.request('/', method='GET', body=self.body)
            self.assertEqual(resp, self.err_resp)
