#!/usr/bin/env python3

import json
import sys

sys.path.append("/home/hannes/projects/bachelor-thesis/src")

from handover.common.communication import ControllerCommunicator

cc = ControllerCommunicator("0.0.0.0", 8080)
print(json.loads(cc.get_rules().content.decode()))
