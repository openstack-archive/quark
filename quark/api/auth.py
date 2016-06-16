# Copyright (c) 2013 Rackspace Hosting Inc.
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

from neutron import context
from neutron import wsgi
from oslo_log import log as logging
import webob.dec
import webob.exc

LOG = logging.getLogger(__name__)


class NoAuthMiddleware(wsgi.Middleware):
    """Return a fake token if one isn't specified."""

    @webob.dec.wsgify(RequestClass=wsgi.Request)
    def __call__(self, req):
        if 'X-Auth-Token' not in req.headers:
            user_id = req.headers.get('X-Auth-User', 'admin')
            project_id = req.headers.get('X-Auth-Project-Id', 'admin')
            res = webob.Response()
            res.headers['X-Auth-Token'] = '%s:%s' % (user_id, project_id)
            res.content_type = 'text/plain'
            res.status = '204'
            return res

        token = req.headers['X-Auth-Token']
        user_id, _sep, project_id = token.partition(':')
        project_id = project_id or user_id
        ctx = context.Context(user_id,
                              project_id,
                              is_admin=True)

        req.environ['neutron.context'] = ctx
        return self.application
