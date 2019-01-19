from ._base import *


class TestCase102(TestCase):
    def __init__(self):
        TestCase.__init__(self,
                          id='102',
                          alt_id='fixed_std_increasing_pps_58_bytes_no_handover',
                          description='Fixed State Transfer Duration. Increasing PPS. 58 Byte Packets. No handover.',
                          pps=[100, 1000, 100],
                          packet_size=58,
                          state_duration=0,
                          reports=PPS_REPORTS,
                          skip_handover=True)
