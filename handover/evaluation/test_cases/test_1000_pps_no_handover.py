from ._base import *


class TestCase100(TestCase):
    def __init__(self):
        TestCase.__init__(self,
                          id='100',
                          alt_id='fixed_std_increasing_pps_1000_bytes_no_handover',
                          description='Fixed State Transfer Duration. Increasing PPS. 1000 Byte Packets. No handover.',
                          pps=[100, 1000, 100],
                          packet_size=1000,
                          state_duration=0,
                          reports=PPS_REPORTS,
                          skip_handover=True)
