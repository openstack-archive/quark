#!/bin/bash
# To build a new container
# docker build -t quark .

echo "Mysql: Starting Container..."
docker run -d -p 3306:3306 --restart=always --name mysql -e MYSQL_ROOT_PASSWORD=password -d mysql

echo "Mysql: Waiting for Mysql to Start..."
# Need to wait for DB to standup
sleep 30
echo "Mysql: Complete - PORT 3306"
echo "------------------------------------------"
echo "                                          "

echo "PHPMyAdmin: Starting Container..."
docker run -d --restart=always --name phpmyadmin --link mysql:mysql -p 8081:80 nazarpc/phpmyadmin
echo "PHPMyAdmin: Complete - http://localhost:8081"
echo "------------------------------------------"
echo "                                          "

echo "ELK: Starting Container..."
docker run --restart=always --name kibana -d -p 514:514 -p 514:514/udp -p 8083:5601 -v /etc/localtime:/etc/localtime:ro pschiffe/rsyslog-elasticsearch-kibana
echo "ELK: Complete - http://localhost:8083"
echo "------------------------------------------"
echo "                                          "

echo "RabbitMQ: Starting Container..."
docker run -d --hostname baserabbitmq -p 8080:15672 -p 5671-5672:5671-5672 -p 15671:15671 -p 4369:4369 -p 25672:25672 --restart=always --name rabbitmq -e RABBITMQ_DEFAULT_USER=admin -e RABBITMQ_DEFAULT_PASS=password -e RABBITMQ_ERLANG_COOKIE='w9efn934ht34t3' rabbitmq:3-management
echo "RabbitMQ: Complete - http://localhost:8080"
echo "------------------------------------------"
echo "                                          "

echo "Neutron/Quark: Starting Container..."
docker run -d -v $(pwd):/opt/quark -v ~/neutron:/opt/configs -p 9696:9696 --link mysql:docker-mysql --link kibana:docker-kibana --link rabbitmq:docker-rabbitmq --name quark stajkowski/quark
# docker run --entrypoint /bin/bash -v $(pwd):/opt/quark -v ~/neutron:/opt/configs -p 9696:9696 --link mysql:docker-mysql --link kibana:docker-kibana --link rabbitmq:docker-rabbitmq --name quark stajkowski/quark
echo "Neutron/Quark: Complete - http://localhost:9696"
echo "------------------------------------------"
echo "                                          "