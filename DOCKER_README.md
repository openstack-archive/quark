# Neutron/Quark docker development environment

## General Info:
Your user needs root privileges - at this point mostly for starting rabbitmq.

**IMPORTANT NOTE:** The container network will not work while RAX Cisco Anyconnect VPN is connected. Disconnect the VPN before doing anything.

## TLDR;
Git clone the quark repo and cd into the repo directory.
Run:

```
$ sudo bash docker_up.sh
```

Test the API with curl like so:

```
$ curl http://localhost:9696/v2.0/networks
```

Make changes to quark code and re-deploy:

```
$ sudo bash docker_reload.sh
```

To cleanup:

```
$ sudo bash docker_down.sh`
```

## General API request flow:
User request → wafflehaus → neutron → quark → db + xen


## Files:
> quark/

> docker_up.sh

> docker_down.sh

> docker_reload.sh

> quark/infrastructure/docker/quark/Dockerfile


## Logs:
To view logs, tail -f this file:
> quark/quark_container_logs/neutron-server.log

## Docker:
Install docker for your OS!

## To build:
Modify Dockerfile, typically in infrastructure/docker/quark/Dockerfile
Run:

```
$ docker build -t raxuser/neutron:quark -f infrastructure/docker/quark/Dockerfile .
```

This will create an image.

```
$ docker images ← will show the image ID
```


Run (note: sudo needs to get root privileges):

```
$ sudo bash docker_up.sh
```

This will create these containers:
> Mysql ← takes 30 sec

> ELK

> RabbitMQ ← requires root

> Redis

> Redis Sentinel

> Neutron/Quark ← takes several minutes


If you want to view what’s going on:

```
$ docker ps → find the neutron/quark container ID
```
```
$ docker attach ID
```

This will start scrolling what’s going.
If after a few minutes you are back at the bash prompt - something went wrong.
Scroll up to see what exactly. Also, may check the log file mentioned above.
If all went well, you should see port 9696 listening (netstat -an | grep 9696). You should be able to query the neutron API, for example:

```
$ curl http://localhost:9696/v2.0/networks
```

You could also:

```
$ tail -f quark/quark_container_logs/neutron-server.log
```

Note: you will have to restart the above tail command every time you re-deploy neutron.

Go to http://localhost:8083, click “Discover” tab, click “time picker” and pick “Today”. This will show all the logs for today in a parsed format.

## To Make Code Changes:
Make your changes to the Quark files in place where you checked them out on your workstation. There is no need to copy files to the containers or back.
After the changes were made, run:

```
$ sudo bash docker_reload.sh
```

This will destroy the old the quark container, start a new quark container, and install the new neutron and quark code.
This operation takes a couple minutes.
After the rebuild is done, all should work.

## Cleanup:
Get the IDs of the containers:

```
$ docker ps -a
```

Remove the unnecessary containers:

```
$ docker rm container_ID
```

List images and get IDs:

```
$ docker images
```

Remove unnecessary images:

```
$ docker rmi image_ID
```

End of document.
