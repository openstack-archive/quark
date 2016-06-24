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

import json

from neutron import wsgi
from oslo_log import log as logging
import webob.dec
import webob.exc

LOG = logging.getLogger(__name__)


class ResponseAsyncIdAdder(object):
    """Return a fake token if one isn't specified."""
    def __init__(self, app, conf):
        self.app = app
        self.conf = conf

    def _get_resp(self, req):
        return req.get_response(self.app)

    def _get_ctx(self, req):
        return req.environ.get('neutron.context')

    @webob.dec.wsgify(RequestClass=wsgi.Request)
    def __call__(self, req):
        resp = self._get_resp(req)
        context = self._get_ctx(req)
        if hasattr(context, 'async_job'):
            try:
                json_body = json.loads(resp.body)
                json_body['job_id'] = context.async_job['job']['id']
                resp.body = json.dumps(json_body)
                resp.headers['job_id'] = context.async_job['job']['id']
            except ValueError:  # bad json not abnormal
                return resp
            except Exception as e:  # Bare exception for anything random
                LOG.error("Uncaught exception: %s" % e)
        return resp


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def wrapper(app):
        return ResponseAsyncIdAdder(app, conf)

    return wrapper
