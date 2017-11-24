#!/usr/bin/python

"""
This example shows how to create a simple network and
how to create docker containers (based on existing images)
to it.
"""
import time

from handover.libs.mininet.log import setLogLevel, info
from handover.libs.mininet.net import Containernet

from handover.conf import *
from handover.libs.mininet.node import OVSSwitch
from handover.libs.mininet.node import RemoteController

CAPTURE_PACKETS = 0


def build_topology(state_transfer_duration=0, responder_count=10, protocol="udp"):
    "Create a network with some docker containers acting as hosts."
    def setup_vnf(vnf):
        vnf.cmd('hsl_layer start -d {} {} '.format(state_transfer_duration, vnf.name))
        vnf.cmd('vnf_impl start {}'.format(vnf.name))
        if CAPTURE_PACKETS:
            vnf.cmd('tcpdump -i {0}-eth0 -w /src/captures/{0}-eth0.pcap&'.format(vnf.name))
            vnf.cmd('tcpdump -i {0}-eth1 -w /src/captures/{0}-eth1.pcap&'.format(vnf.name))
            vnf.cmd('tcpdump -i {0}-tap0 -w /src/captures/{0}-tap0.pcap&'.format(vnf.name))
            vnf.cmd('tcpdump -i {0}-tap1 -w /src/captures/{0}-tap1.pcap&'.format(vnf.name))

    def setup_host(host):
        host.cmd('export PYTHONPATH=/src/')
        host.cmd('ethtool -K {}-eth0 tx off'.format(host.name))
        if CAPTURE_PACKETS:
            host.cmd('tcpdump -i {0}-eth0 -w /src/captures/{0}-eth0.pcap&'.format(host.name))
            host.cmd('tcpdump -i {0}-eth1 -w /src/captures/{0}-eth1.pcap&'.format(host.name))

    def setup_switch(switch):
        if CAPTURE_PACKETS:
            switch.cmd('tcpdump -i {0}-eth1 -w {1}/captures/{0}-eth1.pcap&'.format(switch.name, SRC_DIR.rstrip('/')))
            switch.cmd('tcpdump -i {0}-eth2 -w {1}/captures/{0}-eth2.pcap&'.format(switch.name, SRC_DIR.rstrip('/')))
            switch.cmd('tcpdump -i {0}-eth3 -w {1}/captures/{0}-eth3.pcap&'.format(switch.name, SRC_DIR.rstrip('/')))

    net = Containernet(controller=RemoteController, cleanup=True)

    info('*** Adding controller\n')
    net.addController('c0')

    info('*** Adding docker containers\n')
    HOST_IMAGE = NODE_IMAGE_NAME
    HOST_NAME = 'd{}'
    HOST_IP = '10.0.0.{}'
    HOST_COUNT = 2
    HOST_VOLUMES = ["{}:/src:rw".format(SRC_DIR)]
    VNF_IMAGE = NODE_IMAGE_NAME
    VNF_NAME = 'vnf{}'
    VNF_COUNT = 2
    VNF_VOLUMES = ["{}:/src:rw".format(SRC_DIR)]

    hosts = [net.addDocker(HOST_NAME.format(idx),
                           ip=HOST_IP.format(idx+100),
                           dimage=HOST_IMAGE,
                           switch_id=1,
                           volumes=HOST_VOLUMES,
                           sysctl={
                            'net.core.wmem_max': 12582912,
                            'net.core.rmem_max': 12582912,
                           })
             for idx in range(1, HOST_COUNT+1)]
    vnfs = [net.addDocker(VNF_NAME.format(idx),
                          dimage=VNF_IMAGE,
                          dpid=hex(idx+1000),
                          volumes=VNF_VOLUMES,
                          sysctl={
                              'net.core.wmem_max': 12582912,
                              'net.core.rmem_max': 12582912,
                          })
            for idx in range(1, VNF_COUNT+1)]

    info('*** Adding switch\n')
    switches = [net.addSwitch('s1', cls=OVSSwitch, dpid="1"),
                net.addSwitch('s2', cls=OVSSwitch, dpid="2")]

    info('*** Creating links\n')
    for s in switches:
        for vnf in vnfs:
            net.addLink(s, vnf)

    net.addLink(switches[0], hosts[0])
    net.addLink(switches[1], hosts[1])

    MAC_TEMPLATE = '00:00:00:00:{:02X}:{:02X}'
    IF_TEMPLATE= 'vnf{}-eth{}'
    for idx, vnf in enumerate(vnfs):
        for if_idx in range(2):
            vnf.setMAC(MAC_TEMPLATE.format(idx+1, if_idx),
                       IF_TEMPLATE.format(idx+1, if_idx))

    info('*** Starting network\n')
    net.start()

    time.sleep(0.5)

    for vnf in vnfs:
        setup_vnf(vnf)
        
    for host in hosts:
        setup_host(host)

    for switch in switches:
        setup_switch(switch)

    hosts[1].cmd('responder -c {} -t {}&'.format(responder_count, protocol))

    return net

if __name__ == '__main__':
    setLogLevel('info')
    build_topology()
