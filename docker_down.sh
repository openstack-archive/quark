#!/bin/bash

echo "Mysql: Stopping & Deleting Container..."
docker stop mysql
docker rm mysql
echo "Mysql: Complete"
echo "-----------------------"
echo "                       "

echo "PHPMyAdmin: Stopping & Deleting Container..."
docker stop phpmyadmin
docker rm phpmyadmin
echo "PHPMyAdmin: Complete"
echo "-----------------------"
echo "                       "

echo "ELK: Stopping & Deleting Container..."
docker stop kibana
docker rm kibana
echo "ELK: Complete"
echo "-----------------------"
echo "                       "

echo "RabbitMQ: Stopping & Deleting Container..."
docker stop rabbitmq
docker rm rabbitmq
echo "RabbitMQ: Complete"
echo "-----------------------"
echo "                       "

echo "Redis: Stopping & Deleting Container..."
docker stop redis
docker rm redis
echo "Redis: Complete"
echo "-----------------------"
echo "                       "

echo "Redis Sentinel: Stopping & Deleting Container..."
docker stop redis-sentinel
docker rm redis-sentinel
echo "Redis Sentinel: Complete"
echo "-----------------------"
echo "                       "

echo "Neutron/Quark: Stopping & Deleting Container..."
docker stop quark
docker rm quark
echo "Neutron/Quark: Complete"
echo "-----------------------"
echo "                       "

rm -rf ./quark_container_logs
rm -rf ./quark_container_venv