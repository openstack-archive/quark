# Copyright 2013 Rackspace Hosting Inc.
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


import contextlib
import cProfile as profiler
import gc
import sys
import time
try:
    import pstats
except Exception:
    # Don't want to force pstats into the venv if it's not always used
    pass

from neutron.api.v2 import attributes
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


def filter_body(context, body, admin_only=None, always_filter=None):
    if not context.is_admin and admin_only:
        for attr in admin_only:
            pop_param(body, attr)
    if always_filter:
        for attr in always_filter:
            pop_param(body, attr)


def attr_specified(param):
    return param is not attributes.ATTR_NOT_SPECIFIED


def timed(fn):
    def _wrapped(*args, **kwargs):
        began = time.time()
        res = fn(*args, **kwargs)
        elapsed = time.time() - began
        LOG.info("Time for %s = %s" % (fn, elapsed))
        return res
    return _wrapped


def profile(output):
    def _inner(fn):
        def _wrapped(*args, **kw):
            result = _profile(output, fn, *args, **kw)
            # uncomment this to see who's calling what
            # stats.print_callers()
            return result
        return _wrapped
    return _inner


def live_profile(fn):
    def _wrapped(*args, **kw):
        elapsed, stat_loader, result = _live_profile(fn, *args, **kw)
        stats = stat_loader()
        stats.sort_stats('cumulative')
        stats.print_stats()
        # uncomment this to see who's calling what
        # stats.print_callers()
        return result
    return _wrapped


def _profile(filename, fn, *args, **kw):
    gc.collect()

    profiler.runctx('result = fn(*args, **kw)', globals(), locals(),
                    filename=filename)

    return locals()['result']


def _live_profile(fn, *args, **kw):
    load_stats = lambda: pstats.Stats()
    gc.collect()

    began = time.time()
    profiler.runctx('result = fn(*args, **kw)', globals(), locals())
    ended = time.time()

    return ended - began, load_stats, locals()['result']


def pop_param(attrs, param, default=None):
    val = attrs.pop(param, default)
    if attr_specified(val):
        return val
    return default


class Command(object):
    def __init__(self, func):
        self.func = func
        self.result = None
        self.called = False

    def __call__(self, *args, **kwargs):
        self.called = True
        self.result = self.func(*args, **kwargs)
        return self.result


class CommandManager(object):
    def __init__(self):
        self.do_commands = []
        self.undo_commands = []

    @contextlib.contextmanager
    def execute(self, exc=None):
        try:
            yield self
        except Exception:
            exc_info = sys.exc_info()
            LOG.exception("Exception in transaction", exc_info=exc_info)
            self.rollback()
            raise exc_info[1]

    def do(self, func):
        cmd = Command(func)
        self.do_commands.append(cmd)
        return cmd

    def undo(self, func):
        cmd = Command(func)
        self.undo_commands.append(cmd)
        return cmd

    def rollback(self):
        do_commands = reversed(self.do_commands)
        for cmd in reversed(self.undo_commands):
            do = do_commands.next()
            if not do.called:
                continue
            try:
                cmd(do.result)
            except Exception:
                LOG.exception("Rollback failed and wasn't caught!")


class retry_loop(object):
    def __init__(self, retry_times, delay=0, backoff=1):
        self._retry_times = retry_times
        self._delay = delay
        self._backoff = backoff

    def __call__(self, f):
        def wrapped_f(*args, **kwargs):
            level = self._retry_times
            current_delay = self._delay
            while level > 0:
                try:
                    return f(*args, **kwargs)
                except Exception:
                    level = level - 1
                    if level > 0:
                        if current_delay > 0:
                            time.sleep(current_delay)
                            if self._backoff > 0:
                                current_delay *= self._backoff

                        LOG.debug("Retrying `%s` %d more times...",
                                  f.func_name, level)
                    else:
                        raise
        return wrapped_f


def pretty_kwargs(**kwargs):
    kwargs_str = ', '.join("%s=%s" % (k, v) for k, v in kwargs.items())
    return kwargs_str
