#!/usr/bin/env python
__author__ = 'Joel Bennett'

import os
import sys
import socket
import ConfigParser

from IPFIX import *
from SplunkLogger import *


## For testing purposes. The following THREE lines.
if not "SPLUNK_HOME" in os.environ:
    APP_PATH = os.path.abspath('..')
else:
    APP_PATH = os.path.join(os.environ["SPLUNK_HOME"], 'etc', 'apps', 'Splunk_TA_IPFIX')
CONFIG_FILE = os.path.join(APP_PATH, 'default', 'ipfix.conf'), os.path.join(APP_PATH, 'local', 'ipfix.conf')
LOG_FILENAME = os.path.join(APP_PATH, 'log', 'appflow.log')
DEBUG_LOG_FILENAME = os.path.join(APP_PATH, 'log', 'debug.log')
# For testing purpose
#CONFIG_FILE = './ipfix.conf'
#LOG_FILENAME = './appflow.log'

# Read config file
Config = ConfigParser.ConfigParser()
Config.read(CONFIG_FILE)
HOST = Config.get('network', 'host')
PORT = int(Config.get('network', 'port'))
PROTOCOL = Config.get('network', 'protocol')
MAX_BYTES = Config.getint('logging', 'maxBytes')
BACKUP_COUNT = Config.getint('logging', 'backupCount')

splunkLogger = SplunkLogger(LOG_FILENAME, MAX_BYTES, BACKUP_COUNT)
debugLogger = SplunkLogger(DEBUG_LOG_FILENAME, MAX_BYTES, BACKUP_COUNT)

# Currently, only support UDP
if PROTOCOL.lower() == 'udp':
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((HOST, PORT))
    sys.stderr.write("Waiting on UDP port:" + str(PORT) + "\n")
    while 1:
        #    The IPFIX Message Header 16-bit Length field limits the length of an
        #    IPFIX Message to 65535 octets, including the header.  A Collecting
        #    Process MUST be able to handle IPFIX Message lengths of up to 65535
        #    octets.
        data, addr = s.recvfrom(65535)
        ipfix = Parser(data, addr, logger=debugLogger)
        if ipfix.data:
            splunkLogger.info(str(ipfix))

else:
    sys.stderr.write("ERROR! Unsupported protocol: " + str(PROTOCOL) + "\nexiting...")
    sys.exit(1)
