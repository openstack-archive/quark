#!/bin/bash
# To build a new container
# docker build -t quark .

mkdir ./quark_container_logs
mkdir ./quark_container_venv

echo "Mysql: Starting Container..."
docker run -d --restart=always -p 3306:3306 --name mysql -e MYSQL_ROOT_PASSWORD=password mysql

echo "Mysql: Waiting for Mysql to Start..."
# Need to wait for DB to standup
sleep 30
docker exec mysql mysql -uroot -ppassword -e "set password = password('')"
echo "Mysql: Complete - PORT 3306"
echo "------------------------------------------"
echo "                                          "

echo "ELK: Starting Container..."
docker run --restart=always --name kibana -d -p 514:514 -p 514:514/udp -p 8083:5601 -v /etc/localtime:/etc/localtime:ro pschiffe/rsyslog-elasticsearch-kibana
echo "ELK: Complete - http://localhost:8083"
echo "------------------------------------------"
echo "                                          "

echo "RabbitMQ: Starting Container..."
docker run -d --restart=always --hostname baserabbitmq -p 8080:15672 -p 5671-5672:5671-5672 -p 15671:15671 -p 4369:4369 -p 25672:25672 --name rabbitmq -e RABBITMQ_DEFAULT_USER=admin -e RABBITMQ_DEFAULT_PASS=password -e RABBITMQ_ERLANG_COOKIE='w9efn934ht34t3' rabbitmq:3-management
echo "RabbitMQ: Complete - http://localhost:8080"
echo "------------------------------------------"
echo "                                          "

echo "Redis: Starting Master Container..."
docker run -d --restart=always -p 6379:6379 -v ~/data/redis0:/data --name=redis stajkowski/redis-master
echo "Redis: Complete - PORT 6379"
echo "------------------------------------------"
echo "                                          "

echo "Redis Sentinel: Starting Sentinel Container..."
docker run -d --restart=always -p 6380:6380 -v ~/data/redis0:/data --link redis:docker-redis --name=redis-sentinel stajkowski/redis-sentinel
echo "Redis Sentinel: Complete - PORT 6380"
echo "------------------------------------------"
echo "                                          "

echo "Neutron/Quark: Starting Container..."
docker run -d -v $(pwd):/opt/quark -v ~/neutron:/opt/configs -v $(pwd)/quark_container_logs:/var/log/neutron -v $(pwd)/quark_container_venv:/opt/venv/lib/python2.7/site-packages/quark -p 9696:9696 --link mysql:docker-mysql --link kibana:docker-kibana --link rabbitmq:docker-rabbitmq --link redis-sentinel:docker-redis-sentinel --name quark stajkowski/quark
# docker run --entrypoint /bin/bash -v $(pwd):/opt/quark -v ~/neutron:/opt/configs -v $(pwd)/quark_container_logs:/var/log/neutron -v $(pwd)/quark_container_venv:/opt/venv -p 9696:9696 --link mysql:docker-mysql --link kibana:docker-kibana --link rabbitmq:docker-rabbitmq --link redis-sentinel:docker-redis-sentinel --name quark stajkowski/quark
echo "Neutron/Quark: Waiting for Neutron to Start..."
# Need to wait for DB to standup
sleep 5
check_count=0
while [ $check_count -lt 175 ]; do
    check=`curl -s http://localhost:9696/v2.0/networks | grep "networks" | wc -l`
    if [ "$check" -gt 0 ]; then
        echo "Seems to be alive!"
        break
    fi
    sleep 1
    check_count=$((check_count+1))
done
echo "Neutron/Quark: Complete - http://localhost:9696"
echo "------------------------------------------"
echo "                                          "

echo "Creating Networks..."
echo "------------------------------------------"
echo "Creating Mac Range..."
echo "                                          "
curl -X POST -H "Content-Type: application/json" -d '{"mac_address_range": {"cidr" : "AA:BB:CC", "tenant_id": "provider"}}' http://localhost:9696/v2.0/mac_address_ranges.json
echo "                                          "
echo "Creating Network..."
echo "                                          "
curl -X POST -H "Content-Type: application/json" -d '{"network": {"id": "00000000-0000-0000-0000-000000000000", "tenant_id": "provider", "name": "public"}}' http://localhost:9696/v2.0/networks
echo "                                          "
echo "Creating Subnets..."
echo "                                          "
curl -X POST -H "Content-Type: application/json" -d '{"subnet": {"network_id": "00000000-0000-0000-0000-000000000000", "segment_id": "blah", "cidr": "10.1.0.0/16", "tenant_id": "derp", "ip_version": "4"}}'  http://localhost:9696/v2.0/subnets
echo "                                          "
curl -X POST -H "Content-Type: application/json" -d '{"subnet": {"network_id": "00000000-0000-0000-0000-000000000000", "segment_id": "blah", "cidr": "10.2.0.0/16", "tenant_id": "derp", "ip_version": "4"}}'  http://localhost:9696/v2.0/subnets
echo "                                          "
curl -X POST -H "Content-Type: application/json" -d '{"subnet": {"network_id": "00000000-0000-0000-0000-000000000000", "segment_id": "blah", "cidr": "10.3.0.0/16", "tenant_id": "derp", "ip_version": "4"}}'  http://localhost:9696/v2.0/subnets
echo "                                          "
curl -X POST -H "Content-Type: application/json" -d '{"subnet": {"network_id": "00000000-0000-0000-0000-000000000000", "segment_id": "blah", "cidr": "10.4.0.0/16", "tenant_id": "derp", "ip_version": "4"}}'  http://localhost:9696/v2.0/subnets
echo "                                          "
echo "Create Networks: Complete - http://localhost:9696"
echo "------------------------------------------"
echo " MAC Range: AA:BB:CC"
echo " NETWORK: 00000000-0000-0000-0000-000000000000"
echo " CIDR: 10.1.0.0/16  SEGMENT_ID: blah TENANT_ID: derp"
echo " CIDR: 10.2.0.0/16  SEGMENT_ID: blah TENANT_ID: derp"
echo " CIDR: 10.3.0.0/16  SEGMENT_ID: blah TENANT_ID: derp"
echo " CIDR: 10.4.0.0/16  SEGMENT_ID: blah TENANT_ID: derp"
echo "------------------------------------------"
echo " COMPLETE!!"
echo "------------------------------------------"
