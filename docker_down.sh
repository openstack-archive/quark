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

echo "Neutron/Quark: Stopping & Deleting Container..."
docker stop quark
docker rm quark
echo "Neutron/Quark: Complete"
echo "-----------------------"
echo "                       "