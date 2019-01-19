from ._base import *


class TestCase103(TestCase):
    def __init__(self):
        TestCase.__init__(self,
                          id='103',
                          alt_id='fixed_pps_increasing_pps_58_bytes_no_handover',
                          description='Fixed PPS. Increasing State Transfer Duration. 58 Byte Packets. No handover.',
                          pps=1000,
                          packet_size=58,
                          state_duration=[0, 1, 0.1],
                          reports=STD_REPORTS,
                          skip_handover=True)
