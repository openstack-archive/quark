#!/usr/bin/env python
import sys

from gunicorn.app import base
from gunicorn import config as gconfig
from neutron.common import config
from neutron.common import utils
from neutron import service  # noqa  For api_workers config value
from oslo_config import cfg
from oslo_log import log as logging


options = [
    cfg.StrOpt('access_log',
               default='/var/log/neutron/http_access.log',
               help='The Access log file to write to.'),
    cfg.StrOpt('error_log',
               default='/var/log/neutron/http_error.log',
               help='The Error log file to write to.'),
    cfg.StrOpt('worker_class',
               default='eventlet',
               help='The type of workers to use.'),
    cfg.IntOpt('worker_connections',
               default=20,
               help='The number of concurrent worker threads.'),
    cfg.IntOpt('limit_request_line',
               default=0,
               help='The maximum size of HTTP request line in bytes.'),
    cfg.StrOpt('loglevel',
               default='debug',
               help='The granularity of Error log outputs.'),
]
cfg.CONF.register_opts(options, 'gunicorn')


LOG = logging.getLogger(__name__)


class Neutron(base.Application):
    def init(self, *args, **kwargs):
        pass

    def load_config(self):
        self.cfg = gconfig.Config(self.usage, prog=self.prog)
        settings = {'bind': '%s:%s' % (cfg.CONF.bind_host, cfg.CONF.bind_port),
                    'workers': cfg.CONF.api_workers,
                    'worker_connections': cfg.CONF.gunicorn.worker_connections,
                    'worker_class': cfg.CONF.gunicorn.worker_class,
                    'proc_name': 'neutron-server',
                    'accesslog': cfg.CONF.gunicorn.access_log,
                    'errorlog': cfg.CONF.gunicorn.error_log,
                    'limit_request_line': cfg.CONF.gunicorn.limit_request_line,
                    'loglevel': cfg.CONF.gunicorn.loglevel,
                    'access_log_format': ' '.join(('%(h)s',
                                                   '%(l)s',
                                                   '%(u)s',
                                                   '%(t)s',
                                                   '"%(r)s"',
                                                   '%(s)s',
                                                   '%(b)s',
                                                   '"%(f)s"',
                                                   '"%(a)s"',
                                                   '%(T)s',
                                                   '%(D)s',)),
                    }

        for k, v in settings.iteritems():
            self.cfg.set(k.lower(), v)

    def load(self):
        return config.load_paste_app(app_name=self.prog)

    def run(self):
        base.Arbiter(self).run()


def main():
    config.init(sys.argv[1:])
    if not cfg.CONF.config_file:
        sys.exit(_("ERROR: Unable to find configuration file via the default"
                   " search paths (~/.neutron/, ~/, /etc/neutron/, /etc/) and"
                   " the '--config-file' option!"))

    config.setup_logging()
    utils.log_opt_values(LOG)

    neutron_api = Neutron(prog='neutron')
    neutron_api.run()


if __name__ == '__main__':
    main()
