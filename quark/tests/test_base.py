# Copyright (c) 2013 OpenStack Foundation
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

import os

from neutron.common import config
from neutron import context
from oslo_config import cfg
import unittest2


class TestBase(unittest2.TestCase):
    '''Class to decide which unit test class to inherit from uniformly.'''

    def setUp(self):
        super(TestBase, self).setUp()
        tox_path = os.environ.get("VIRTUAL_ENV")
        cfg.CONF.set_override('state_path', tox_path)

        neutron_conf_path = "%s/etc/neutron/neutron.conf" % tox_path
        try:
            open(neutron_conf_path, "r")
        except IOError:
            open(neutron_conf_path, "w")

        args = ['--config-file', neutron_conf_path]
        config.init(args=args)

        self.context = context.Context('fake', 'fake', is_admin=False)
        self.admin_context = context.Context('fake', 'fake', is_admin=True,
                                             load_admin_roles=False)

        class FakeContext(object):
            def __new__(cls, *args, **kwargs):
                return super(FakeContext, cls).__new__(cls)

            def __enter__(*args, **kwargs):
                pass

            def __exit__(*args, **kwargs):
                pass

        self.context.session.begin = FakeContext
