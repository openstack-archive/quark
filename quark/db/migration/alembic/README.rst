Generic single-database configuration.

See http://alembic.readthedocs.org/en/latest/tutorial.html for more usage.


Examples:
=========

- Applying Migration Locally (using sqlite3)

.. code-block:: bash

    $ quark-db-manage --database-connection sqlite:////home/vagrant/dev/quark.db
        upgrade 1284c81cf727

    INFO  [alembic.migration] Context impl SQLiteImpl.                                    
    INFO  [alembic.migration] Will assume non-transactional DDL.                          
    INFO  [alembic.migration] Running upgrade 4358d1b8cc75 -> 1284c81cf727, 
    create lswitch and lswitch port orphaned tables


- Checking Current Version Locally After Migration

.. code-block:: bash

    $ quark-db-manage --database-connection sqlite:////home/vagrant/dev/quark.db
        current

    INFO  [alembic.migration] Context impl SQLiteImpl.
    INFO  [alembic.migration] Will assume non-transactional DDL.
    Current revision for sqlite:////home/vagrant/dev/quark.db: 
    4358d1b8cc75 -> 1284c81cf727 (head), 
    create lswitch and lswitch port orphaned tables


Using Neutron.conf
=================

If you prefer to use a `neutron.conf` instead of passing args it would look like this

.. code-block:: bash

    [database]
    connection=sqlite:///home/vagrant/dev/quark.db

and you would use it like so

.. code-block:: bash
    
    $ quark-db-manage --config-file /home/vagrant/dev/neutron.conf
        upgrade 1284c81cf727

    INFO  [alembic.migration] Context impl SQLiteImpl.                                    
    INFO  [alembic.migration] Will assume non-transactional DDL.                          
    INFO  [alembic.migration] Running upgrade 4358d1b8cc75 -> 1284c81cf727, 
    create lswitch and lswitch port orphaned tables
