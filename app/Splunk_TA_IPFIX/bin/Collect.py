#!/usr/bin/env python
__author__ = 'Joel Bennett'

from os import path
import sys
import socket
import logging

from SplunkLogger import *
from ConfigParser import ConfigParser

from IPFIX import Parser, MODULE_PATH
# We assume that the MODULE is inside the /bin/ of an app
APP_PATH = path.dirname(path.dirname(MODULE_PATH))
LOG_PATH = path.join(APP_PATH, 'log')
CONFIG_FILE = path.join(APP_PATH, 'default', 'ipfix.conf'), \
              path.join(APP_PATH, 'local', 'ipfix.conf')


# Read config file
Config = ConfigParser()
Config.read(CONFIG_FILE)
HOST = Config.get('network', 'host')
PORT = Config.getint('network', 'port')
PROTOCOL = Config.get('network', 'protocol')

# These two options are how we mitigate disk IO and network bursts
BUFFER_BYTES = Config.getint('network','buffer')
LEVEL = Config.get('logging', 'level')
LOG_LEVEL = logging.getLevelName(LEVEL)

# These two options control file log rotation
BUFFER_OUTPUT = Config.getboolean('logging','useFileForOutput')
MAX_BYTES = Config.getint('logging', 'maxBytes')
BACKUP_COUNT = Config.getint('logging', 'backupCount')

splunkLogger = SplunkLogger(path.join(LOG_PATH, 'output.log'), MAX_BYTES, BACKUP_COUNT)
debugLogger = SplunkLogger(path.join(LOG_PATH, 'debug.log'), MAX_BYTES, BACKUP_COUNT)
debugLogger.setLevel(LOG_LEVEL)

# Currently, only support UDP
if PROTOCOL.lower() == 'udp':
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, BUFFER_BYTES)
    s.bind((HOST, PORT))
    while 1:
        #    The IPFIX Message Header 16-bit Length field limits the length of an
        #    IPFIX Message to 65535 octets, including the header.  A Collecting
        #    Process MUST be able to handle IPFIX Message lengths of up to 65535
        #    octets.
        data, addr = s.recvfrom(65535)
        ipfix = Parser(data, addr, logger=debugLogger)
        if ipfix.data:
            if BUFFER_OUTPUT:
                splunkLogger.info(str(ipfix))
            else:
                print str(ipfix)

else:
    sys.stderr.write("ERROR! Unsupported protocol: " + str(PROTOCOL) + "\nexiting...")
    sys.exit(1)
