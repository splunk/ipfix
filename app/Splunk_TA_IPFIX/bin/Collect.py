#!/usr/bin/env python
__author__ = 'Joel Bennett'

import os
import sys
import socket
import ConfigParser
import logging

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

# Read config file
Config = ConfigParser.ConfigParser()
Config.read(CONFIG_FILE)
HOST = Config.get('network', 'host')
PORT = Config.getint('network', 'port')
PROTOCOL = Config.get('network', 'protocol')

# These two options are how we mitigate disk IO and network bursts
BUFFER_BYTES = Config.getint('network','buffer')
LEVEL = Config.get('logging', 'level')
LOG_LEVEL = logging.getLevelName(LEVEL)

# These two options control file log rotation
MAX_BYTES = Config.getint('logging', 'maxBytes')
BACKUP_COUNT = Config.getint('logging', 'backupCount')

splunkLogger = SplunkLogger(LOG_FILENAME, MAX_BYTES, BACKUP_COUNT)
debugLogger = SplunkLogger(DEBUG_LOG_FILENAME, MAX_BYTES, BACKUP_COUNT)
debugLogger.setLevel(LOG_LEVEL)

# Currently, only support UDP
if PROTOCOL.lower() == 'udp':
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, BUFFER_BYTES)
    s.bind((HOST, PORT))
    sys.stderr.write("Waiting on UDP {}:{}\n".format(HOST, PORT))
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
