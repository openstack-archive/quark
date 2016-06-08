import eventlet
eventlet.monkey_patch(socket=True, select=True, time=True)

import sys
import time

from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging as messaging
from oslo_service import service as common_service
from oslo_utils import excutils

from neutron._i18n import _
from neutron._i18n import _LE
from neutron.common import config
from neutron.common import rpc as n_rpc
from neutron.db import api as session
from neutron import service

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


class QuarkRpcTestCallback(object):
    target = messaging.Target(version='1.0', namespace=None)

    def stuff(self, context, **kwargs):
        return {"status": "okay"}


class QuarkAsyncPlugin(object):
    def __init__(self):
        pass

    def _setup_rpc(self):
        self.endpoints = [QuarkRpcTestCallback()]

    def start_rpc_listeners(self):
        """Configure all listeners here"""
        self._setup_rpc()
        self.conn = n_rpc.create_connection()
        self.conn.create_consumer(CONF.QUARK_ASYNC.topic, self.endpoints,
                                  fanout=False)
        return self.conn.consume_in_threads()


def serve_rpc():

    if cfg.CONF.QUARK_ASYNC.rpc_workers < 1:
        cfg.CONF.set_override('rpc_workers', 1, "QUARK_ASYNC")

    try:
        plugins = [QuarkAsyncPlugin()]
        rpc = service.RpcWorker(plugins)
        session.dispose()  # probaby not needed, but maybe
        launcher = common_service.ProcessLauncher(CONF, wait_interval=1.0)
        launcher.launch_service(rpc, workers=CONF.QUARK_ASYNC.rpc_workers)

        return launcher
    except Exception:
        with excutils.save_and_reraise_exception():
            LOG.exception(_LE('Unrecoverable error: please check log for '
                              'details.'))


def start_api_and_rpc_workers():
    pool = eventlet.GreenPool()

    quark_rpc = serve_rpc()
    pool.spawn(quark_rpc.wait)

    pool.waitall()


def boot_server(server_func):
    # the configuration will be read into the cfg.CONF global data structure
    config.init(sys.argv[1:])
    config.setup_logging()
    config.set_config_defaults()
    if not cfg.CONF.config_file:
        sys.exit(_("ERROR: Unable to find configuration file via the default"
                   " search paths (~/.neutron/, ~/, /etc/neutron/, /etc/) and"
                   " the '--config-file' option!"))
    try:
        server_func()
    except KeyboardInterrupt:
        pass
    except RuntimeError as e:
        sys.exit(_("ERROR: %s") % e)


def main():
    boot_server(start_api_and_rpc_workers)


class QuarkRpcTestApi(object):
    """This class is used for testing QuarkRpcTestCallback."""
    def __init__(self):
        target = messaging.Target(topic=CONF.QUARK_ASYNC.topic)
        self.client = n_rpc.get_client(target)

    def stuff(self, context):
        cctxt = self.client.prepare(version='1.0')
        return cctxt.call(context, 'stuff')


class QuarkAsyncTestContext(object):
    """This class is used for testing QuarkRpcTestCallback."""
    def __init__(self):
        self.time = time.ctime()

    def to_dict(self):
        return {"application": "rpc-client", "time": time.ctime()}


def test_main():
    config.init(sys.argv[1:])
    config.setup_logging()
    config.set_config_defaults()
    if not cfg.CONF.config_file:
        sys.exit(_("ERROR: Unable to find configuration file via the default"
                   " search paths (~/.neutron/, ~/, /etc/neutron/, /etc/) and"
                   " the '--config-file' option!"))
    context = QuarkAsyncTestContext()  # typically context is neutron context
    client = QuarkRpcTestApi()
    LOG.info(client.stuff(context))
    time.sleep(0)  # necessary for preventing Timeout exceptions


if __name__ == "__main__":
    main()
