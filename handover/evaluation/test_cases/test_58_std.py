from ._base import *


class TestCase003(TestCase):
    def __init__(self):
        TestCase.__init__(self,
                          id='003',
                          alt_id='fixed_pps_increasing_pps_58_bytes',
                          description='Fixed PPS. Increasing State Transfer Duration. 58 Byte Packets',
                          pps=1000,
                          packet_size=58,
                          state_duration=[0, 1, 0.1],
                          reports=STD_REPORTS)
