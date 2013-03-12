import sqlalchemy as sa
from sqlalchemy import types
from sqlalchemy.dialects import sqlite


class INET(types.TypeDecorator):
    impl = types.LargeBinary

    def load_dialect_impl(self, dialect):
        if dialect.name == 'sqlite':
            # IPv6 is 128 bits => 2^128 == 3.4e38 => 39 digits
            return dialect.type_descriptor(sqlite.CHAR(39))
        return dialect.type_descriptor(self.impl)

    def process_bind_param(self, value, dialect):
        if value is None:
            return value

        if dialect.name == 'sqlite':
            return str(value)

        return value

    def process_result_value(self, value, dialect):
        if value is None:
            return value

        if dialect.name == 'sqlite':
            return long(value)

        return value


class MACAddress(types.TypeDecorator):
    impl = types.BigInteger

    def load_dialect_impl(self, dialect):
        if dialect.name == 'sqlite':
            return dialect.type_descriptor(sqlite.CHAR)
        return dialect.type_descriptor(self.impl)
