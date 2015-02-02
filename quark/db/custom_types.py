# Copyright (c) 2012 OpenStack Foundation
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

from sqlalchemy.dialects import sqlite
from sqlalchemy import types


class INET(types.TypeDecorator):
    impl = types.CHAR

    def load_dialect_impl(self, dialect):
        # IPv6 is 128 bits => 2^128 == 3.4e38 => 39 digits
        return dialect.type_descriptor(types.CHAR(39))

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        return str(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        return long(value)


class MACAddress(types.TypeDecorator):
    impl = types.BigInteger

    def load_dialect_impl(self, dialect):
        if dialect.name == 'sqlite':
            return dialect.type_descriptor(sqlite.CHAR)
        return dialect.type_descriptor(self.impl)
