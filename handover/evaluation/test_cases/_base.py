
class TestReportAxis:
    def __init__(self, stat, label, unit):
        self.stat = stat
        self.label = label
        self.unit = unit


class TestReport:
    def __init__(self, x_axis, y_axis):
        self.x_axis = x_axis
        self.y_axis = y_axis


class TestCase:
    def __init__(self,
                 id='',
                 alt_id='',
                 description='',
                 handover_count=100,
                 reset_network=True,
                 protocol="udp",
                 pps=None,
                 packet_size=None,
                 state_duration=None,
                 reports=None):
        self.id = id
        self.alt_id = alt_id
        self.description = description
        self.handover_count = handover_count
        self.reset_network = reset_network
        self.protocol = protocol
        self.pps = pps
        self.packet_size = packet_size
        self.state_duration = state_duration
        self.reports = reports

    def get_step_count(self):
        if type(self.pps) is list:
            return int((self.pps[1] - self.pps[0]) / self.pps[2]) + 1
        if type(self.state_duration) is list:
            return int((self.state_duration[1] - self.state_duration[0]) / self.state_duration[2]) + 1
        return 1

    def get_pps(self, step):
        if type(self.pps) is list:
            return self.pps[0] + self.pps[2] * step
        return self.pps

    def get_packet_size(self, step):
        if type(self.packet_size) is list:
            return self.packet_size[0] + self.packet_size[2] * step
        return self.packet_size

    def get_state_duration(self, step):
        if type(self.state_duration) is list:
            return self.state_duration[0] + self.state_duration[2] * step
        return self.state_duration


def get_reports(x_axis):
    return [
        TestReport(
            x_axis,
            TestReportAxis('ctrl_buffer', 'Control Buffer Usage', 'kB')
        ),
        TestReport(
            x_axis,
            TestReportAxis('handover_duration', 'Handover Duration', 'ms')
        ),
        TestReport(
            x_axis,
            TestReportAxis('vnf_buffer', 'VNF Buffer Usage', 'kB')
        ),
        TestReport(
            x_axis,
            TestReportAxis('all_buffer', 'Overall Buffer Usage', 'kB')
        ),
        TestReport(
            x_axis,
            TestReportAxis('packet_delay', 'Maximum Packet Delay', 'ms')
        ),
        TestReport(
            x_axis,
            TestReportAxis('missing_packets', 'Missing Packets', '#')
        ),
        TestReport(
            x_axis,
            TestReportAxis('reordered_packets', 'Reordered Packets', '#')
        ),
        TestReport(
            x_axis,
            TestReportAxis('duplicated_packets', 'Duplicated Packets', '#')
        ),
    ]

PPS_REPORT_X_AXIS = TestReportAxis('pps', 'Packet Rate', '1/s')
PPS_REPORTS = get_reports(PPS_REPORT_X_AXIS)

STD_REPORT_X_AXIS = TestReportAxis('state_duration', 'State Transfer Duration', 'ms')
STD_REPORTS = get_reports(STD_REPORT_X_AXIS)