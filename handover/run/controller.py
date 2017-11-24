#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys

from ryu.cmd import manager


if __name__ == '__main__':
    sys.argv.append('--ofp-tcp-listen-port')
    sys.argv.append('6633')
    sys.argv.append('handover.controller.app')
    # sys.argv.append('--verbose')
    # sys.argv.append('--enable-debugger')
    manager.main()