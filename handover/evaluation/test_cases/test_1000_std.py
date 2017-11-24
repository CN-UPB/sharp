from ._base import *


class TestCase001(TestCase):
    def __init__(self):
        TestCase.__init__(self,
                          id='001',
                          alt_id='fixed_pps_increasing_std_1000_bytes',
                          description='Fixed PPS. Increasing State Transfer Duration. 1000 Byte Packets',
                          pps=1000,
                          packet_size=1000,
                          state_duration=[0, 1, 0.1],
                          reports=STD_REPORTS)
