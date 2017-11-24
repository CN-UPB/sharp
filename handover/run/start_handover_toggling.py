from handover.common.communication import ControllerCommunicator


def add_rule(vnf_id, **kwargs):
    cc = ControllerCommunicator("0.0.0.0", 8080)
    cc.add_handover_rule(vnf_id, **kwargs)


if __name__ == '__main__':
    next_vnf = 1
    prio = 10
    print ("start by pressing enter")
    raw_input()
    while True:
        add_rule(vnf_id=next_vnf + 1,
                 priority=prio,
                 ipv4_src='10.0.0.101')
        print ("handover to {}".format(next_vnf + 1))
        next_vnf = (next_vnf + 1) % 2
        prio += 1
        raw_input()
