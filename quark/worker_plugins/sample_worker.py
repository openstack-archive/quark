# Copyright 2016 Rackspace Hosting Inc.
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
import sys
import time

from neutron._i18n import _
from neutron.common import config
from neutron.common import rpc as n_rpc
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging as messaging

from quark.plugin_modules import networks as network_api
from quark.worker_plugins import base_worker


CONF = cfg.CONF
LOG = logging.getLogger(__name__)
TEST_TOPIC = 'quark'
VERSION = "1.0"


class QuarkRpcTestCallback(object):
    target = messaging.Target(version='1.0', namespace=None)

    def stuff(self, context, **kwargs):
        LOG.debug(context)
        networks = network_api.get_networks(context)
        return {"networks": networks, "status": "okay"}


class QuarkAsyncPluginTest(base_worker.QuarkAsyncPluginBase):
    versions = [VERSION]
    TOPIC = "quark"

    def __init__(self, topic=TOPIC):
        super(QuarkAsyncPluginTest, self).__init__(topic)
        self.callbacks = [QuarkRpcTestCallback()]


class QuarkRpcTestApi(object):
    """This class is used for testing QuarkRpcTestCallback."""
    def __init__(self, topic):
        target = messaging.Target(topic=topic)
        self.client = n_rpc.get_client(target)

    def stuff(self, context):
        cctxt = self.client.prepare(version='1.0')
        return cctxt.call(context, 'stuff')


def main():
    config.init(sys.argv[1:])
    config.setup_logging()
    config.set_config_defaults()
    if not cfg.CONF.config_file:
        sys.exit(_("ERROR: Unable to find configuration file via the default"
                   " search paths (~/.neutron/, ~/, /etc/neutron/, /etc/) and"
                   " the '--config-file' option!"))
    client = QuarkRpcTestApi(TEST_TOPIC)
    LOG.info(client.stuff(base_worker.get_test_context()))
    time.sleep(0)  # necessary for preventing Timeout exceptions
