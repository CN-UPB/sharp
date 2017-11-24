import argparse
import json

import matplotlib.pyplot as plt
import numpy as np

import multiprocessing

from handover.evaluation.evaluation_conf import *
from handover.evaluation.test_cases.test_1000_pps import TestCase000
from handover.evaluation.test_cases.test_1000_std import TestCase001
from handover.evaluation.test_cases.test_58_pps import TestCase002
from handover.evaluation.test_cases.test_58_std import TestCase003
DATES = []


def get_latest_test(test_case):
    test_dir = os.path.join(EVAL_RESULTS_DIRECTORY, str(test_case.id))
    if not os.path.exists(test_dir):
        test_dir = os.path.join(EVAL_RESULTS_DIRECTORY, str(test_case.alt_id))
    latest_date = str(max(list(map(int, os.listdir(test_dir)))))
    return os.path.join(test_dir, latest_date)


def get_date_text_dir(test_case, dates):
    test_dir = os.path.join(EVAL_RESULTS_DIRECTORY, str(test_case.id))
    if not os.path.exists(test_dir):
        test_dir = os.path.join(EVAL_RESULTS_DIRECTORY, str(test_case.alt_id))
    for path in [os.path.join(test_dir, str(date)) for date in dates]:
        if os.path.exists(path):
            return path
    return None


def load_handovers(test_case, step_dir):
    data = []
    for handover in range(test_case.handover_count):
        handover_dir = os.path.join(step_dir, str(handover))
        ctrl_filename = os.path.join(handover_dir, CONTROLLER_RESULTS_FILENAME)
        gen_filename = os.path.join(handover_dir, GENERATOR_RESULTS_FILENAME)
        if os.path.exists(handover_dir) and os.path.exists(ctrl_filename) and os.path.exists(gen_filename):
            ho_data = {}
            with open(ctrl_filename) as ctrl:
                ho_data['ctrl'] = json.load(ctrl)
            with open(gen_filename) as gen:
                try:
                    ho_data['gen'] = json.load(gen)
                except ValueError:
                    print "No data for step {} handover {}".format(os.path.split(step_dir)[-1], handover)
                    continue
            data.append(ho_data)
    return data


def get_data_for_axis(data, axis):
    try:
        generator_version = data[0]['gen']['generator_version']
    except KeyError:
        generator_version = 1

    if axis.stat == 'ctrl_buffer':
        return [sum([b for key, b in ho['ctrl']['buffered_bytes'].items()]) / 1000.0 for ho in data]
    elif axis.stat == 'vnf_buffer':
        if generator_version == 1:
            return [sum([ho['gen']['packet_size'] for p in ho['gen']['packets'] if p[3]]) / 1000.0 for ho in data]
        elif generator_version == 2:
            return [sum([ho['gen']['packet_size'] for p in ho['gen']['packets'] if p[4] or p[6]]) / 1000.0 for ho in data]
    elif axis.stat == 'handover_duration':
        return [(ho['ctrl']['end_time'] - ho['ctrl']['start_time']) * 1000.0 for ho in data]
    elif axis.stat == 'packet_delay':
        if generator_version == 1:
            return [max([p[5] for p in ho['gen']['packets']]) * 1000 for ho in data]
        elif generator_version == 2:
            return [max([p[3] for p in ho['gen']['packets']]) * 1000 for ho in data]
    elif axis.stat == 'missing_packets':
        return [len(ho['gen']['missing_packets']) for ho in data]
    elif axis.stat == 'reordered_packets':
        return [len(ho['gen']['reordered_packets']) for ho in data]
    elif axis.stat == 'duplicated_packets':
        return [len(ho['gen']['duplicate_packets']) for ho in data]
    return []


def get_position_for_step(test_case, axis, step):
    if axis.stat == 'pps':
        return test_case.get_pps(step)
    elif axis.stat == 'state_duration':
        return int(test_case.get_state_duration(step) * 1000)


def get_axis_label(axis):
    if axis.unit:
        return '{} ({})'.format(axis.label, axis.unit)
    return axis.label


def generate_report(test_case, report, number, dates):
    x_positions = []
    y_data = []

    test_dir = None
    if dates:
        test_dir = get_date_text_dir(test_case, dates)

    if not test_dir:
        test_dir = get_latest_test(test_case)

    print test_dir

    for step in range(test_case.get_step_count()):
        step_dir = os.path.join(test_dir, str(step))
        if os.path.exists(step_dir):
            x_positions.append(get_position_for_step(test_case, report.x_axis, step))
            data = load_handovers(test_case, step_dir)
            if data:
                y_data.append(get_data_for_axis(data, report.y_axis))

    try:
        x_widths = [(x_positions[1] - x_positions[0]) / 2 for i in range(len(x_positions))]
    except IndexError:
        x_widths = [(get_position_for_step(test_case, report.x_axis, 1) - get_position_for_step(test_case, report.x_axis, 0)) / 2]

    fig = plt.figure(None, figsize=(9, 6))

    ax = fig.add_subplot(111)

    bp = ax.boxplot(y_data,
                    positions=x_positions,
                    widths=x_widths,
                    showfliers=False)

    if y_data and y_data[0] and not any([min(d) for d in y_data]):
        ax.yaxis.set_ticks(np.arange(-1, 2, 1))

    ax.set_xlim(xmin=x_positions[0] - x_widths[0] * 0.7, xmax=x_positions[-1] + x_widths[-1] * 0.7)
    ax.set_xlabel(get_axis_label(report.x_axis))
    ax.set_ylabel(get_axis_label(report.y_axis))
    # ax.set_yticklabels(ax.yaxis.get_majorticklabels(), rotation=45)
    ax.set_xticklabels(ax.xaxis.get_majorticklabels(), rotation=45)

    fig.tight_layout()

    fig.savefig(os.path.join(GRAPHS_DIRECTORY, 'eval_{}_{}_{}.pdf'.format(test_case.id, report.y_axis.stat, report.x_axis.stat)),
                format='pdf')


def generate_report_mp(args):
    generate_report(*args)


def generate_reports_for_test_case(test_case, dates):
    pool = multiprocessing.Pool()
    args = [[test_case, report, idx+1, dates] for idx, report in enumerate(test_case.reports)]
    pool.map(generate_report_mp, args)

if __name__ == '__main__':
    argp = argparse.ArgumentParser()
    argp.add_argument('--timestamp', '-t', nargs='?', type=int, action='append',
                      help='List additional timestamps for graph generation')
    argp.add_argument('--output', '-o', type=str, help='Output directory')

    args = argp.parse_args()

    if not 'date' in args or not args.date:
        args.date = []

    plt.rcParams.update({'font.size': 22,
                         'figure.autolayout': True})

    if args.output:
        if os.path.exists(args.output):
            GRAPHS_DIRECTORY = args.output
        else:
            print "{} does not exist".format(args.output)
            exit(-1)

    generate_reports_for_test_case(TestCase000(), args.date + DATES)
    generate_reports_for_test_case(TestCase001(), args.date + DATES)
    generate_reports_for_test_case(TestCase002(), args.date + DATES)
    generate_reports_for_test_case(TestCase003(), args.date + DATES)

    # plt.show()
