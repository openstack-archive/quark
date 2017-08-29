#!/bin/bash

echo "Neutron/Quark: Stopping & Deleting Container..."
docker stop quark
docker rm quark
echo "Neutron/Quark: Complete"
echo "-----------------------"
echo "                       "

# NOTE(alexm): there was a request not to remove these log files on reload
rm -rf ./quark_container_logs/*
rm -rf ./quark_container_venv/*

echo "Neutron/Quark: Starting Container..."
# NOTE(alexm): may need to add -v ~/neutron:/opt/configs when quark is caught up with upstream neutron
docker run -d -v $(pwd):/opt/quark -v $(pwd)/quark_container_logs:/var/log/neutron -v $(pwd)/quark_container_venv:/opt/venv/lib/python2.7/site-packages/quark -p 9696:9696 --link mysql:docker-mysql --link kibana:docker-kibana --link rabbitmq:docker-rabbitmq --link redis-sentinel:docker-redis-sentinel --name quark raxuser/neutron:quark

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
echo "Neutron/Quark - Complete - http://localhost:9696"
