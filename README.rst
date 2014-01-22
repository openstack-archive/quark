=====
quark
=====

Current Build Status
====================
.. image:: https://api.travis-ci.org/rackerlabs/quark.png
    :target: https://travis-ci.org/rackerlabs/quark

Caution
=======
Quark is not currently designed to work with `DevStack <http://devstack.org>`_ (but it can with the instructions below).  We mention this because these instructions can become invalid if and when changes are pushed to DevStack.  Please also not that once Quark+Neutron+DevStack+Tempest are wired up, the Tempest tests are failing. Please watch `this Quark Github Issue <https://github.com/rackerlabs/quark/issues/50>`_ for updates on this.

Dependencies
===================
aiclib

Install with DevStack and Neutron
=================================

- Ensure you have a user already with sudo rights.  If you need one, do this as root::

    /usr/sbin/adduser stack
    echo "stack ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

- Switch to user with sudo rights::

    sudo su - stack  # or whatever user you already have (instead of stack)

- Clone devstack::

    git clone https://github.com/openstack-dev/devstack

- Go into devstack folder::

    cd devstack

- Create the local.conf configuration file that DevStack needs (localrc is inside it now) with Neutron as an anabled service (NOTE: This notation is explained `here <http://devstack.org/configuration.html>`_)::

    [[local|localrc]]
    DATABASE_PASSWORD=password
    ADMIN_PASSWORD=password
    SERVICE_PASSWORD=password
    SERVICE_TOKEN=password
    RABBIT_PASSWORD=password
    # Enable Logging
    LOGFILE=/opt/stack/logs/stack.sh.log
    VERBOSE=True
    LOG_COLOR=True
    SCREEN_LOGDIR=/opt/stack/logs
    # Pre-requisite
    ENABLED_SERVICES=rabbit,mysql,key
    # Horizon (always use the trunk)
    ENABLED_SERVICES+=,horizon
    HORIZON_REPO=https://github.com/openstack/horizon
    HORIZON_BRANCH=master
    # Nova
    ENABLED_SERVICES+=,n-api,n-crt,n-obj,n-cpu,n-cond,n-sch
    IMAGE_URLS+=",https://launchpad.net/cirros/trunk/0.3.0/+download/cirros-0.3.0-x86_64-disk.img"
    # Glance
    ENABLED_SERVICES+=,g-api,g-reg
    # Neutron
    ENABLED_SERVICES+=,q-api,q-svc,q-agt,q-dhcp,q-l3,q-lbaas,q-meta,neutron
    # Cinder
    ENABLED_SERVICES+=,cinder,c-api,c-vol,c-sch
    # Tempest
    ENABLED_SERVICES+=,tempest

- Install Devstack::
    
    ./stack.sh

- Install aiclib::
  
    sudo pip install aiclib   
    # the reason for sudo here is if you don't you'll get permission denied when it tries to install to /usr/local/lib/python2.7/dist/packages

- Install quark::

    cd /opt/stack  #the folder where devstack installed all the services
    git clone https://github.com/rackerlabs/quark
    cd quark
    sudo python setup.py develop
    # the reason for sudo here is if you don't you'll get permission denied when it tries to install to /usr/local/lib/python2.7/dist/packages

- Validate quark installed::

    pip freeze | grep quark
    # should see something like:
    # -e git+http://github.com/rackerlabs/quark@ff5b05943b44a44712b9fc352065a414bb2a6bf9#egg=quark-master

- Stop Neutron by going into the screen session and going to the q-svc window and pressing ctrl-C::

    screen -r  # or go into devstack clone and then type ./rejoin-stack.sh
    # press ctrl+6 to go to q-svc window
    ctrl+C

- Now edit the /etc/neutron/neutron.conf file to setup Quark as the core plugin::

    vim /etc/neutron/neutron.conf
    #  add 'core_plugin - quark.plugin.Plugin' (current example of core_plugin is near line 70)

- Go back into screen and restart neutron (q-svc window)::

    screen -r  # or go into folder where you cloned devstack then type ./rejoin-stack.sh
    # go to q-svc window (ctrl+a, 6 currently does it)
    # previous command that devstack used to start neutron should be in history, press up arrow key to see it

- You shouldn't receive any errors.  To validate Quark has started up, you can scroll up in q-svc screen window (ctrl+a, esc, page-up) and look for the following lines::

    DEBUG neutron.service [-] core_plugin = quark.plugin.Plugin
    ...
    DEBUG neutron.service [-] QUARK.default_ipam_strategy=ANY
    DEBUG neutron.service [-] QUARK.default_net_strategy={}
    DEBUG neutron.service [-] QUARK.default_network_type=BASE
    DEBUG neutron.service [-] QUARK.ipam_driver=quark.ipam.QuarkIpam
    DEBUG neutron.service [-] QUARK.ipam_reuse_after=7200
    DEBUG neutron.service [-] QUARK.net_driver=quark.drivers.base.BaseDriver
    DEBUG neutron.service [-] QUARK.strategy_driver=quark.network_strategy.JSONStrategy

GOTCHAS
=======
- you won't be able to create ports until you've added at least one mac_address_range (use `this <https://gist.github.com/jmeridth/8561910>`_ script to do it, changing host IP and admin password)
