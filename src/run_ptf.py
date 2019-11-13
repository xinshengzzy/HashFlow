#!/usr/bin/env python

# Copyright 2013-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys
import os
import subprocess
import argparse

if __name__ == "__main__":
    args= ['./ptf', '--pypath', '/root/bf-sde-8.2.0/install/lib/python2.7/site-packages/p4testutils', '--pypath', '/root/bf-sde-8.2.0/install/lib/python2.7/site-packages/p4testutils/..', '--test-dir', '/root/bf-sde-8.2.0/./pkgsrc/p4-examples/ptf-tests/stful', '--pypath', '/root/bf-sde-8.2.0/install/lib/python2.7/site-packages', '--pypath', '/root/bf-sde-8.2.0/install/lib/python2.7/site-packages/tofinopd/myswitch', '--pypath', '/root/bf-sde-8.2.0/install/lib/python2.7/site-packages/tofino', '--interface', '0-0@veth1', '--interface', '0-1@veth3', '--interface', '0-2@veth5', '--interface', '0-3@veth7', '--interface', '0-4@veth9', '--interface', '0-5@veth11', '--interface', '0-6@veth13', '--interface', '0-7@veth15', '--interface', '0-8@veth17', '--interface', '0-64@veth251', '--socket-recv-size', '10240', "--test-params=arch='Tofino';target='asic-model';use_pi='False';traffic_gen='None';config_file='filename';drivers_test_info='None';test_seed='None';num_pipes='4';port_mode='100G';counter_byte_adjust='0';setup=False;cleanup=False;p4c='';thrift_server='localhost';grpc_server='localhost'"]
    env= {'LANG': 'en_US.UTF-8', 'USERNAME': 'root', 'TERM': 'xterm', 'SHELL': '/bin/bash', 'SUDO_COMMAND': '/usr/bin/env PATH=/root/bf-sde-8.2.0/install/bin:/root/bf-sde-8.2.0/install/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/lib/platform-config/current/onl/bin:/lib/platform-config/current/onl/sbin:/lib/platform-config/current/onl/lib/bin:/lib/platform-config/current/onl/lib/sbin PYTHONPATH=/root/bf-sde-8.2.0/install/lib/python2.7/site-packages/p4testutils:/root/bf-sde-8.2.0/install/lib/python2.7/site-packages/tofinopd/:/root/bf-sde-8.2.0/install/lib/python2.7/site-packages/tofino:/root/bf-sde-8.2.0/install/lib/python2.7/site-packages/: python /root/bf-sde-8.2.0/install/lib/python2.7/site-packages/p4testutils/run_ptf_tests.py --arch Tofino --target asic-model --test-dir /root/bf-sde-8.2.0/./pkgsrc/p4-examples/ptf-tests/stful --port-info None --thrift-server localhost --cpu-port 64 --cpu-veth 251 --num-pipes 4 --socket-recv-size 10240', 'PYTHONPATH': '/root/bf-sde-8.2.0/install/lib/python2.7/site-packages:/root/bf-sde-8.2.0/install/lib/python2.7/site-packages/p4testutils:/root/bf-sde-8.2.0/install/lib/python2.7/site-packages/tofinopd/:/root/bf-sde-8.2.0/install/lib/python2.7/site-packages/tofino:/root/bf-sde-8.2.0/install/lib/python2.7/site-packages/:', 'SUDO_UID': '0', 'SUDO_GID': '0', 'LOGNAME': 'root', 'USER': 'root', 'PATH': '/root/bf-sde-8.2.0/install/bin:/root/bf-sde-8.2.0/install/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/lib/platform-config/current/onl/bin:/lib/platform-config/current/onl/sbin:/lib/platform-config/current/onl/lib/bin:/lib/platform-config/current/onl/lib/sbin', 'MAIL': '/var/mail/root', 'SUDO_USER': 'root', 'HOME': '/root'}
    child = subprocess.Popen(args, env=env)
    child.wait()
    sys.exit(child.returncode)
