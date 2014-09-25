# Copyright 2014 Openstack Foundation
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

from neutron.openstack.common import log as logging


LOG = logging.getLogger(__name__)


class retry_loop(object):
    def __init__(self, retry_times):
        self._retry_times = retry_times

    def __call__(self, f):
        def wrapped_f(*args, **kwargs):
            level = self._retry_times
            while level > 0:
                try:
                    return f(*args, **kwargs)
                except Exception:
                    level = level - 1
                    if level > 0:
                        LOG.debug("Retrying `%s` %d more times...",
                                  f.func_name, level)
                    else:
                        raise
        return wrapped_f
