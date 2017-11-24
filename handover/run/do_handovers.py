
from handover.common.communication import ControllerCommunicator

next_vnf = 1
prio = 10
rules = []
cc = ControllerCommunicator("0.0.0.0", 8080)


def add_rule(vnf_id, **kwargs):
    cc.add_handover_rule(vnf_id, **kwargs)


def add_next_rule(vnf_id=None):
    global next_vnf
    global prio
    global rules

    if vnf_id:
        next_vnf = int(vnf_id) - 1

    add_rule(vnf_id=next_vnf + 1,
             priority=prio,
             ipv4_src='10.0.0.101',
             udp_src=24242)
    rules.append([prio - 9, next_vnf])
    print ("handover to {}".format(next_vnf + 1))
    next_vnf = (next_vnf + 1) % 2
    prio += 1


def remove_rule(id):
    global rules
    global next_vnf
    cc.remove_handover_rule(id)
    try:
        rule = [rule for rule in rules if rule[0] == id][0]
        rules.remove(rule)
        print ("removed rule {}. expected vnf {}".format(id, rules[-1][1] + 1))
        next_vnf = (rules[-1][1] + 1) % 2
    except IndexError:
        print ("no rule {}".format(id))


if __name__ == '__main__':
    print ("start by pressing enter")
    input()
    add_next_rule()
    while True:
        print (', '.join(['{}:{}'.format(id, vnf + 1) for id, vnf in rules]))
        cmd = input()
        if cmd.startswith('a'):
            add_next_rule(cmd[1:].strip())
        elif cmd.startswith('r'):
            id = int(cmd.replace('r', '').strip())
            remove_rule(id)
