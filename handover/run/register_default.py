#!/usr/bin/env python3
import sys

sys.path.append("/home/hannes/projects/bachelor-thesis/src")


from handover.common.communication import ControllerCommunicator


def register_default():
    cc = ControllerCommunicator("0.0.0.0", 8080)
    cc.register_switch(1, True)
    cc.register_switch(2, False)
    cc.register_vnf(("00:00:00:00:01:00", 1), ("00:00:00:00:01:01", 1))
    cc.register_vnf(("00:00:00:00:02:00", 2), ("00:00:00:00:02:01", 2))

if __name__ == '__main__':
    register_default()