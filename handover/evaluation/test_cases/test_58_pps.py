from ._base import *


class TestCase002(TestCase):
    def __init__(self):
        TestCase.__init__(self,
                          id='002',
                          alt_id='fixed_std_increasing_pps_58_bytes',
                          description='Fixed State Transfer Duration. Increasing PPS. 58 Byte Packets',
                          pps=[200, 3000, 200],
                          packet_size=58,
                          state_duration=0,
                          reports=PPS_REPORTS)
