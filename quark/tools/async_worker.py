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
import eventlet
eventlet.monkey_patch(socket=True, select=True, time=True)

import inspect
import itertools
import sys

from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import service as common_service
from oslo_utils import excutils
from stevedore import extension

from neutron._i18n import _
from neutron._i18n import _LE
from neutron.common import config
from neutron.db import api as session
from neutron import service

from quark.worker_plugins import base_worker

service_opts = [
    cfg.StrOpt('topic',
               help=_('Topic for messaging to pub/sub to')),
    cfg.StrOpt('transport_url',
               help=_('Connection string for transport service')),
    cfg.IntOpt('periodic_interval',
               default=40,
               help=_('Seconds between running periodic tasks')),
    cfg.IntOpt('rpc_workers',
               default=1,
               help=_('Number of RPC worker processes for service')),
    cfg.IntOpt('periodic_fuzzy_delay',
               default=5,
               help=_('Range of seconds to randomly delay when starting the '
                      'periodic task scheduler to reduce stampeding. '
                      '(Disable by setting to 0)')),
]
CONF = cfg.CONF
CONF.register_opts(service_opts, "QUARK_ASYNC")
LOG = logging.getLogger(__name__)
VERSION = "1.0"
PLUGIN_EP = 'quark.worker_plugin'


class QuarkAsyncServer(object):
    def __init__(self):
        self.plugins = []
        self._register_extensions(VERSION)

    def _load_worker_plugin_with_module(self, module, version):
        classes = inspect.getmembers(module, inspect.isclass)
        loaded = 0
        for cls_name, cls in classes:
            if hasattr(cls, 'versions'):
                if version not in cls.versions:
                    continue
            else:
                continue
            if issubclass(cls, base_worker.QuarkAsyncPluginBase):
                LOG.debug("Loading plugin %s" % cls_name)
                plugin = cls()
                self.plugins.append(plugin)
                loaded += 1
        LOG.debug("Found %d possible plugins and loaded %d" %
                  (len(classes), loaded))

    def _register_extensions(self, version):
        for name, module in itertools.chain(self._discover_via_entrypoints()):
            self._load_worker_plugin_with_module(module, version)

    def _discover_via_entrypoints(self):
        emgr = extension.ExtensionManager(PLUGIN_EP, invoke_on_load=False)
        return ((ext.name, ext.plugin) for ext in emgr)

    def start_api_and_rpc_workers(self):
        pool = eventlet.GreenPool()

        quark_rpc = self.serve_rpc()
        pool.spawn(quark_rpc.wait)

        pool.waitall()

    def serve_rpc(self):
        if cfg.CONF.QUARK_ASYNC.rpc_workers < 1:
            cfg.CONF.set_override('rpc_workers', 1, "QUARK_ASYNC")

        try:
            rpc = service.RpcWorker(self.plugins)
            session.dispose()  # probaby not needed, but maybe
            launcher = common_service.ProcessLauncher(CONF, wait_interval=1.0)
            launcher.launch_service(rpc, workers=CONF.QUARK_ASYNC.rpc_workers)

            return launcher
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE('Unrecoverable error: please check log for '
                                  'details.'))

    def run(self):
        self.start_api_and_rpc_workers()


def main():
    config.init(sys.argv[1:])
    config.setup_logging()
    config.set_config_defaults()
    if not cfg.CONF.config_file:
        sys.exit(_("ERROR: Unable to find configuration file via the"
                   " default search paths (~/.neutron/, ~/, /etc/neutron/,"
                   " /etc/) and the '--config-file' option!"))
    try:
        QuarkAsyncServer().run()
    except KeyboardInterrupt:
        pass
    except RuntimeError as e:
        sys.exit(_("ERROR: %s") % e)


if __name__ == "__main__":
    main()
