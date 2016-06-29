#!/bin/bash

echo "Neutron/Quark: Stopping & Deleting Container..."
docker stop quark
docker rm quark
echo "Neutron/Quark: Complete"
echo "-----------------------"
echo "                       "

echo "Neutron/Quark: Starting Container..."
docker run -d -v $(pwd):/opt/quark -v ~/neutron:/opt/configs -p 9696:9696 --link mysql:docker-mysql --link kibana:docker-kibana --link rabbitmq:docker-rabbitmq --link redis-sentinel:docker-redis-sentinel --name quark stajkowski/quark
echo "Neutron/Quark - Complete - http://localhost:9696"