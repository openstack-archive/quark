# Copyright 2015 Openstack Foundation
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
# License for the specific language governing permissions and limitations
#  under the License.

import json
import mock
from oslo_log import log as logging

from quark.api.extensions import ports_quark
from quark.tests.functional.base import BaseFunctionalTest

LOG = logging.getLogger(__name__)


class TestAPIExtensionPortsQuark(BaseFunctionalTest):
    def test_QuarkPortsUpdateHandler(self):
        mock_plugin = mock.MagicMock()
        mock_request = mock.MagicMock()
        mock_response = mock.MagicMock()
        body = '"lots of stuff"'
        port_id = "I_am_a_port"

        handler = ports_quark.QuarkPortsUpdateHandler(mock_plugin)
        self.assertEqual(handler._plugin, mock_plugin)

        mock_plugin.post_update_port.return_value = {"id": port_id,
                                                     "body": body.strip('"')}
        mock_request.body = body
        mock_request.path_url = '/v2.0/ports/{}'.format(port_id)
        expected = ('{{"port": {{"id": "{0}", "body": "{1}"}}}}'
                    ''.format(port_id, body.strip('"')))
        result = handler.handle(mock_request, mock_response)
        self.assertEqual(json.loads(expected), json.loads(result))
