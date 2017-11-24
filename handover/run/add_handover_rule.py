from handover.common.communication import ControllerCommunicator


def add_rule(vnf_id, **kwargs):
    cc = ControllerCommunicator("0.0.0.0", 8080)
    cc.add_handover_rule(vnf_id, **kwargs)


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 2 :
        add_rule(sys.argv[1], **{arg.split('='[0]): arg.split('=')[1] for arg in sys.argv[2:]})
    else:
        add_rule(vnf_id=2,
                 priority=10,
                 ipv4_src='10.0.0.101',
                 tcp_src=24242)

