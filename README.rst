=====
quark
=====

Current Build Status
====================
.. image:: https://api.travis-ci.org/jkoelker/quark.png
    :target: https://travis-ci.org/jkoelker/quark


Why is nothing being commited to the database?
==============================================

Quark uses and relies upon the `transaction` module, something at the
end of the wsgi request needs to commit the transaction, or transaction
aware databases (MySQL InnoDB, Postgres, et. al) will never commit.


The following neutron api-paste.ini enables `repoze.tm2` to in the
pipeline after authentication so transactions are started coming
up the pipeline and commited coming down


.. code:: ini

    [composite:neutron]
    use = egg:Paste#urlmap
    /: neutronversions
    /v2.0: neutronapi_v2_0

    [composite:neutronapi_v2_0]
    use = call:neutron.auth:pipeline_factory
    noauth = egg:repoze.tm2#tm extensions neutronapiapp_v2_0
    keystone = authtoken keystonecontext egg:repoze.tm2#tm extensions neutronapiapp_v2_0

    [filter:keystonecontext]
    paste.filter_factory = neutron.auth:NeutronKeystoneContext.factory

    [filter:authtoken]
    paste.filter_factory = keystoneclient.middleware.auth_token:filter_factory

    [filter:extensions]
    paste.filter_factory = neutron.api.extensions:plugin_aware_extension_middleware_factory

    [app:neutronversions]
    paste.app_factory = neutron.api.versions:Versions.factory

    [app:neutronapiapp_v2_0]
    paste.app_factory = neutron.api.v2.router:APIRouter.factory
