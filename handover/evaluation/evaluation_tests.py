#!/usr/bin/env python

import argparse
import inspect
import json
import shutil
import subprocess
import sys
import time

from handover.conf import *
from handover.evaluation.test_cases._base import TestCase

sys.path.insert(0, os.path.join(SRC_DIR, 'handover/libs'))

import docker
from docker.errors import APIError

from handover.containernet_setup import build_topology
from handover.common.communication import ControllerCommunicator

from handover.evaluation.evaluation_conf import *


REPORT_FILENAME = '24242.report'


def setup_network(test_case, test_step):
    net = build_topology(test_case.get_state_duration(test_step), protocol=test_case.protocol)
    return net


def start_controller(docker_client):
    hc = docker_client.create_host_config(
        network_mode='host',
        privileged=True,
        binds={
            SRC_DIR: {'bind': '/opt/project', 'mode': 'rw'}
        }
    )
    try:
        controller_container = docker_client.create_container(name="mn.controller",
                                                              image='osrg/ryu',
                                                              command="python /opt/project/handover/run/controller.py",
                                                              environment={'PYTHONPATH': '/opt/project'},
                                                              host_config=hc,
                                                              volumes=['/opt/project']
                                                              )
        docker_client.start(controller_container)
        return controller_container
    except APIError:
        reset_net(docker_client)
        return start_controller(docker_client)


def restart_container(docker_client, ctrl_container):
    docker_client.restart(ctrl_container, timeout=1)


def register_default(controller):
    while not controller.is_ready():
        time.sleep(0.5)
    time.sleep(1)
    controller.register_switch(1, True)
    controller.register_switch(2, False)
    controller.register_vnf(("00:00:00:00:01:00", 1), ("00:00:00:00:01:01", 1))
    controller.register_vnf(("00:00:00:00:02:00", 2), ("00:00:00:00:02:01", 2))


def start_components(docker_client, test_case, controller, test_step):
    ctrl_container = start_controller(docker_client)
    register_default(controller)
    net = setup_network(test_case, test_step)
    return ctrl_container, net


def start_generator(test_case, container_net, test_step, test_id=0, temp=False):
    vnf_host = container_net.nameToNode['d1']
    vnf_host.cmd('generator -r {} -i {} -s {} -t {} -p {} {}&'.format(test_case.get_pps(test_step),
                                                                      test_id,
                                                                      test_case.get_packet_size(test_step),
                                                                      test_case.protocol,
                                                                      24242 if not temp else 24243,
                                                                      '10.0.0.102'))


def stop_generator(container_net):
    vnf_host = container_net.nameToNode['d1']
    vnf_host.cmd('killall python')


def do_handover(controller, test_case):
    controller.add_handover_rule(2,
                                 priority=10,
                                 ipv4_src='10.0.0.101',
                                 **{test_case.protocol + '_src': 24242})


def wait_for_handover_finished(controller, timeout=60):
    t_start = time.time()
    statistics = controller.get_handover_statistics(0)
    while not statistics or not statistics['finished']:
        if time.time() - t_start > timeout:
            print "Error: Handover finish timeout reached!"
            return None
        time.sleep(0.1)
        statistics = controller.get_handover_statistics(0)
        print ".",
        sys.stdout.flush()
    print " done."
    return statistics


def collect_generator_statistics(results_dir, test_case, current_id, current_step):
    report_name = os.path.join(GENERATOR_RESULTS_DIRECTORY,
                               '{}_{}pps_{}b'.format(current_id,
                                                     test_case.get_pps(current_step),
                                                     test_case.get_packet_size(current_step)),
                               REPORT_FILENAME)
    results_report_name = os.path.join(results_dir, GENERATOR_RESULTS_FILENAME)
    while not os.path.exists(report_name):
        time.sleep(0.5)
    time.sleep(0.5)
    shutil.copy(report_name, results_report_name)
    os.remove(report_name)

    data = json.load(open(results_report_name))
    print '{} pps, {} actual pps'.format(data['packets_per_second'], data['actual_packets_per_second'])
    print '{} missing, {} reordered'.format(len(data['missing_packets']), len(data['reordered_packets']))


def save_controller_stats(results_dir, stats):
    with open(os.path.join(results_dir, CONTROLLER_RESULTS_FILENAME), 'w+') as ctrl_report:
        json.dump(stats, ctrl_report)


def create_handover_results_directory(results_dir, test_step, handover):
    handover_results_directory = os.path.join(results_dir, str(test_step))
    try:
        os.mkdir(handover_results_directory)
    except OSError:
        pass
    handover_results_directory = os.path.join(handover_results_directory, str(handover))
    try:
        os.mkdir(handover_results_directory)
    except OSError:
        pass
    return handover_results_directory


def create_test_case_directory(test_case, date):
    try:
        os.mkdir(EVAL_RESULTS_DIRECTORY)
    except OSError:
        pass
    results_directory = os.path.join(EVAL_RESULTS_DIRECTORY, str(test_case.id))
    try:
        os.mkdir(results_directory)
    except OSError:
        pass
    results_directory = os.path.join(results_directory, str(int(time.time())) if not date else str(date))
    try:
        os.mkdir(results_directory)
    except OSError:
        pass
    return results_directory


def try_remove_container(docker_client, name):
    try:
        docker_client.stop(name, timeout=1)
    except APIError:
        pass
    try:
        docker_client.remove_container(name)
    except APIError:
        pass


def reset_net(docker_client):
    with open(os.devnull, 'w') as FNULL:
        p = subprocess.Popen('sudo mn -c', shell=True, stdout=FNULL, stderr=FNULL)
        p.communicate()
    try_remove_container(docker_client, 'mn.d1')
    try_remove_container(docker_client, 'mn.d2')
    try_remove_container(docker_client, 'mn.vnf1')
    try_remove_container(docker_client, 'mn.vnf2')
    try_remove_container(docker_client, 'mn.controller')


def stop_vnfs(net):
    for vnf_name in ['vnf1', 'vnf2']:
        vnf = net.nameToNode[vnf_name]
        vnf.cmd('/src/poc/vnf/vnf_impl.py stop')
        vnf.cmd('/src/poc/vnf/hsl_layer.py stop')


def restart_components(docker_client, test_case, controller, net, test_step):
    if net:
        stop_vnfs(net)
        net.stop()
    reset_net(docker_client)

    return start_components(docker_client, test_case, controller, test_step)


def shutdown(dc, ctrl, net):
    print "Shutting down controller"
    dc.stop(ctrl)
    dc.remove_container(ctrl)
    print "Shutting down mininet"
    net.stop()


def get_continue_parameter(results_dir):
    max_step = max([int(n) for n in os.listdir(results_dir)] + [0])
    step_dir = os.path.join(results_dir, str(max_step))
    max_handover = max([int(n) for n in os.listdir(step_dir)] + [0])
    return max_step, max_handover


def run_test(test_case, start_step, start_handover, date):
    print "Running test case {} ({})".format(test_case.id, test_case.description)
    results_directory = create_test_case_directory(test_case, date)

    if date and not start_step:
        start_step, start_handover = get_continue_parameter(results_directory)

    docker_client = docker.Client(base_url='unix://var/run/docker.sock')
    cc = ControllerCommunicator("0.0.0.0", 8080)
    ctrl = net = None
    step_count = test_case.get_step_count()
    all_time = 0
    count = 0
    total_count = (step_count - start_step) * test_case.handover_count - start_handover
    for test_step in range(start_step, step_count):
        print "*** STEP {} / {} ***".format(test_step+1, step_count)
        for current_handover in range(start_handover, test_case.handover_count):
            retry = 0
            while True: # retry as often as needed
                print "*** HANDOVER {} / {} ***".format(current_handover + 1, test_case.handover_count)
                start_time = time.time()
                handover_results_directory = create_handover_results_directory(results_directory,
                                                                               test_step,
                                                                               current_handover)
                handover_id = 100000 + current_handover
                # restart network for test
                print "(1/6) Starting Network"
                ctrl, net = restart_components(docker_client, test_case, cc, net, test_step)
                # wait until network has settled
                time.sleep(1)
                # start generator once to generate the default entries for this flow
                print "(2/6) Preparing Default Routes"
                start_generator(test_case, net, test_step, True)
                time.sleep(0.5)
                # stop pre generator again
                stop_generator(net)
                time.sleep(0.5)
                # start real generator
                print "(3/6) Starting Packet Generator"
                start_generator(test_case, net, test_step, handover_id)
                time.sleep(0.5)
                # instruct the handover
                print "(4/6) Executing Handover"
                do_handover(cc, test_case)
                # wait for handover to be finished and then collect stats
                print "(5/6) Wait For Handover To Finish"
                ctrl_stats = wait_for_handover_finished(cc)
                if ctrl_stats is None:
                    stop_generator(net)
                    retry += 1
                    print("Retry no. {}!".format(retry))
                    continue  # retry (while True)
                time.sleep(1)
                # stop generator and collect controller stats
                print "(6/6) Collecting Data"
                stop_generator(net)
                collect_generator_statistics(handover_results_directory, test_case, handover_id, test_step)
                save_controller_stats(handover_results_directory, ctrl_stats)

                # time tracking
                duration = time.time() - start_time
                all_time += duration
                count += 1
                print '{}s left ({}s)'.format((total_count - count) * (all_time / count), duration)
                break # stop loop if handover was fine
        start_handover = 0

    if ctrl:
        shutdown(docker_client, ctrl, net)


def clear_old_results():
    if os.path.exists(GENERATOR_RESULTS_DIRECTORY):
        shutil.rmtree(GENERATOR_RESULTS_DIRECTORY)
    os.mkdir(GENERATOR_RESULTS_DIRECTORY)


def run_tests(test_case_id, step, handover, date):
    clear_old_results()

    test_cases = load_tests()

    for test_case in test_cases:
        if not test_case_id or test_case_id == test_case.id:
            run_test(test_case, step, handover, date)


def load_tests():
    test_cases = []
    for key, mod in sys.modules.items():
        if key.startswith('handover.evaluation.test_cases.t'):
            for name, obj in inspect.getmembers(mod, inspect.isclass):
                if TestCase in obj.__bases__:
                    test_cases.append(obj())
    return test_cases

if __name__ == "__main__":
    argp = argparse.ArgumentParser()
    argp.add_argument('--date', '-d', dest='date', type=int, default=0)
    argp.add_argument('--test-case', '-t', dest='test_case_id', type=str, default='')
    argp.add_argument('--step', '-s', dest='step', type=int, default=0)
    argp.add_argument('--handover', '-o', dest='handover', type=int, default=0)

    args = argp.parse_args()
    run_tests(args.test_case_id, args.step, args.handover, args.date)

