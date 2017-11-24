#!/usr/bin/env bash

DOCKER_NAMES="mn.d1 mn.d2 mn.vnf1 mn.vnf2 mn.controller"

sudo killall python

if [ "$(docker ps -qa -f name=mn.vnf1)" ] || [ "$(docker ps -qa -f name=mn.d1)" ]; then
    mn -c
fi
if [ "$(docker ps -qa -f name=mn.controller)" ]; then
    docker kill mn.controller
    docker rm mn.controller
fi
