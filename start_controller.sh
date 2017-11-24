#!/usr/bin/env bash

sudo docker run -v `pwd`:/opt/project --net=host -e "PYTHONPATH=/opt/project" --name="mn.controller" -it osrg/ryu python /opt/project/handover/run/controller.py