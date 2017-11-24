import os

import matplotlib.pyplot as plt
import numpy as np

from evaluation_conf import GRAPHS_DIRECTORY


def generate_constant_pps_increased_state():
    pps = 1000
    state_size = 1
    ho_duration = 0.07
    initial_duration = 0.01
    x = np.arange(0, 100.0, 1.0)
    y_opennf = 3 * x * state_size + 2 * pps * ho_duration
    y_sharp = [2 * pps * initial_duration] * x.size

    fig = plt.figure(None, figsize=(9, 6))
    ax = fig.add_subplot(111)
    ax.set_xlabel('State Size (kB)')
    ax.set_ylabel('Packets Processed (#)')
    opennf, = ax.plot(x, y_opennf, label='OpenNF')
    sharp, = ax.plot(x, y_sharp, label='SHarP')
    ax.legend(handles=[opennf, sharp])

    fig.tight_layout()

    fig.savefig(os.path.join(GRAPHS_DIRECTORY, 'theoretical_eval_state.pdf'), format='pdf')


def generate_constant_state_increased_pps():
    state_size = 10
    ho_duration = 0.07
    initial_duration = 0.01
    x = np.arange(100, 10000, 100)
    y_opennf = 3 * state_size + 2 * x * ho_duration
    y_sharp = 2 * x * initial_duration

    fig = plt.figure(None, figsize=(9, 6))
    ax = fig.add_subplot(111)
    ax.set_xlabel('Packet Per Second (1/s)')
    ax.set_ylabel('Packets Processed (#)')
    opennf, = ax.plot(x, y_opennf, label='OpenNF')
    sharp, = ax.plot(x, y_sharp, label='SHarP')
    ax.legend(handles=[opennf, sharp])

    # ax.set_xticklabels(ax.xaxis.get_majorticklabels(), rotation=45)
    fig.tight_layout()

    fig.savefig(os.path.join(GRAPHS_DIRECTORY, 'theoretical_eval_pps.pdf'), format='pdf')


def generate_increased_delay():
    delay = np.arange(0.0, 100.0, 0.1)
    release_speed = 10
    y_sharp_1000pps = (delay * 1) * (1 + 1.0/release_speed)
    y_sharp_2000pps = (delay * 2) * (1 + 1.0/release_speed)
    y_sharp_5000pps = (delay * 5) * (1 + 1.0/release_speed)
    y_sharp_10000pps = (delay * 10) * (1 + 1.0/release_speed)

    fig = plt.figure(None, figsize=(9, 6))
    ax = fig.add_subplot(111)
    ax.set_xlabel('Network Delay (ms)')
    ax.set_ylabel('Packets Processed (#)')
    sharp_10k, = ax.plot(delay, y_sharp_10000pps, label='10 000 pps')
    sharp_5k, = ax.plot(delay, y_sharp_5000pps, label='5000 pps')
    sharp_2k, = ax.plot(delay, y_sharp_2000pps, label='2000 pps')
    sharp_1k, = ax.plot(delay, y_sharp_1000pps, label='1000 pps')
    ax.legend(handles=[sharp_10k, sharp_5k, sharp_2k, sharp_1k])

    # ax.set_xticklabels(ax.xaxis.get_majorticklabels(), rotation=45)
    fig.tight_layout()

    fig.savefig(os.path.join(GRAPHS_DIRECTORY, 'theoretical_eval_delay.pdf'), format='pdf')



plt.rcParams.update({'font.size': 22,
                    'figure.autolayout': True})

generate_constant_pps_increased_state()
generate_constant_state_increased_pps()
generate_increased_delay()
plt.show()




