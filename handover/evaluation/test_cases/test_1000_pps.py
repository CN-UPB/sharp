from ._base import *


class TestCase000(TestCase):
    def __init__(self):
        TestCase.__init__(self,
                          id='000',
                          alt_id='fixed_std_increasing_pps_1000_bytes',
                          description='Fixed State Transfer Duration. Increasing PPS. 1000 Byte Packets',
                          pps=[200, 3000, 200],
                          packet_size=1000,
                          state_duration=0,
                          reports=PPS_REPORTS)
