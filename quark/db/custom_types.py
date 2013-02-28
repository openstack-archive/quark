import sqlalchemy as sa
from sqlalchemy import types
from sqlalchemy.dialects import sqlite


class INET(types.TypeDecorator):
    impl = types.LargeBinary

    def load_dialect_impl(self, dialect):
        if dialect.name == 'sqlite':
            return dialect.type_descriptor(sqlite.CHAR)
        return dialect.type_descriptor(self.impl)


class MACAddress(types.TypeDecorator):
    impl = types.BigInteger

    def load_dialect_impl(self, dialect):
        if dialect.name == 'sqlite':
            return dialect.type_descriptor(sqlite.CHAR)
        return dialect.type_descriptor(self.impl)
