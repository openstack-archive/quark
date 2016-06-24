# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|

  config.vm.box = "stajkowski/quark-dev"
  config.vm.hostname = "neutron.local.com"

  config.vm.network :forwarded_port, guest: 6379, host: 6379 # Redis
  config.vm.network :forwarded_port, guest: 9696, host: 9696 # Neutron
  config.vm.network :forwarded_port, guest: 8080, host: 8080 # RabbitMQ
  config.vm.network :forwarded_port, guest: 8081, host: 8081 # PHPMyAdmin
  config.vm.network :forwarded_port, guest: 8082, host: 3306 # Mysql DB
  config.vm.network :forwarded_port, guest: 8083, host: 8083 # Kibana

  config.vm.provider :virtualbox do |vb|
    vb.customize [
      "modifyvm", :id,
      "--memory", "2048",
    ]
  end

  # Base Provisioning
  config.vm.provision "shell", privileged: true, inline: <<-SHELL
    # General Installation
    apt-get update
    apt-get install -y python-pip python-dev git wget libmysqlclient-dev build-essential libssl-dev libffi-dev python-dev rsyslog mysql-client
    pip install virtualenv

    # Configure Rsyslog and Provision DB
    echo 'local0.*    @@127.0.0.1:514' > /etc/rsyslog.d/60-neutron.conf
    service rsyslog restart
    mysql -h 127.0.0.1 -u root -ppassword -e "CREATE DATABASE neutron"

    # Update setuptools
    wget https://bootstrap.pypa.io/ez_setup.py -O - | sudo python

    # Make our directories
    mkdir /opt/neutron /opt/quark /opt/venv /var/log/neutron

    # Create Virtualenv
    cd /opt/venv
    virtualenv . --distribute
    source bin/activate

    # Clone Neutron
    cd /opt
    git clone https://github.com/openstack/neutron
    cd /opt/neutron && pip install -r requirements.txt && pip install -r test-requirements.txt
    python setup.py develop

  SHELL

  # Quark Installation - will run again on vagrant reload
  config.vm.provision :file, source: ".", destination: "~", run: "always"

  config.vm.provision "shell", run: "always", privileged: true, inline: <<-SHELL

    # Clean source dir on reload
    rm -rf /opt/quark/*
    cd /opt/venv
    source bin/activate

    # Copy and install Quark
    cp -R /home/vagrant/quark/* /opt/quark
    cd /opt/quark
    git init
    pip install -U -r requirements.txt
    python setup.py develop

  SHELL

  # Copy over configuration files
  config.vm.provision :file, source: "./vagrant.neutron.conf", destination: "~/neutron_conf", run: "always"
  config.vm.provision :file, source: "./vagrant.apipaste.ini", destination: "~/apipaste_ini", run: "always"

  config.vm.provision "shell", run: "always", privileged: true, inline: <<-SHELL

    # Put configuration files in place and start Neutron
    cp /home/vagrant/neutron_conf /opt/venv/etc/neutron.conf
    cp /home/vagrant/apipaste_ini /opt/venv/etc/api-paste.ini
    # Needed for reload, permissions get fuzzy here
    chmod -R 0777 ~/*
    source /opt/venv/bin/activate
    quark-db-manage --config-file /opt/venv/etc/neutron.conf upgrade head
    neutron-server --config-file /opt/venv/etc/neutron.conf

  SHELL

end
