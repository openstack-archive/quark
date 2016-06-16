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

import functools

from neutron.api import extensions
from neutron import manager
from neutron_lib import exceptions as n_exc
from oslo_log import log as logging
LOG = logging.getLogger(__name__)


class Diagnostician(object):
    def __init__(self, plugin):
        self.plugin = plugin

    def diag_not_implemented(self, res, id, input):
        LOG.warning("Diagnostics not implemented on resource %ss." % res)
        raise n_exc.ServiceUnavailable()

    def diagnose(self, res, input, req, id):
        LOG.debug("Requested diagnostics fields %s on resource %s with id %s"
                  % (input['diag'], res, id))
        return getattr(
            self.plugin, 'diagnose_%s' % res.replace('-', '_'),
            functools.partial(self.diag_not_implemented, res))(
                req.context, id, input['diag'])


class Diagnostics(extensions.ExtensionDescriptor):
    def get_name(self):
        return "Diagnostics"

    def get_alias(self):
        return "diagnostics"

    def get_description(self):
        return "Diagnostics extension"

    def get_namespace(self):
        return "None"

    def get_updated(self):
        return "never"

    def get_actions(self):
        diagnose = Diagnostician(manager.NeutronManager.get_plugin()).diagnose
        resources = ['port', 'subnet', 'network']
        return (extensions.ActionExtension('%ss' % res, 'diag',
                functools.partial(diagnose, res)) for res in resources)
