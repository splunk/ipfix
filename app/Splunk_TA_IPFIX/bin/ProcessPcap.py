#!/usr/bin/env python
__author__ = 'Joel Bennett'

from os import path, environ
import sys
from struct import unpack
from ConfigParser import ConfigParser
from PcapReader import PcapReader

from IPFIX import *
from SplunkLogger import *


## For testing purposes. The following THREE lines.
if not "SPLUNK_HOME" in environ:
    APP_PATH = path.abspath('..')
else:
    APP_PATH = path.join(environ["SPLUNK_HOME"], 'etc', 'apps', 'Splunk_TA_IPFIX')
CONFIG_FILE = path.join(APP_PATH, 'default', 'ipfix.conf'), path.join(APP_PATH, 'local', 'ipfix.conf')
LOG_FILENAME = path.join(APP_PATH, 'log', 'appflow.log')
DEBUG_LOG_FILENAME = path.join(APP_PATH, 'log', 'debug.log')

# Read config file
Config = ConfigParser()
Config.read(CONFIG_FILE)
PROTOCOL = 'pcap'
HOST = Config.get('network', 'host')
PORT = Config.getint('network', 'port')
PROTOCOL = Config.get('network', 'protocol')
MAX_BYTES = Config.getint('logging', 'maxBytes')
BACKUP_COUNT = Config.getint('logging', 'backupCount')

splunkLogger = SplunkLogger(LOG_FILENAME, MAX_BYTES, BACKUP_COUNT)
debugLogger = SplunkLogger(DEBUG_LOG_FILENAME, MAX_BYTES, BACKUP_COUNT)

# ProcessPcap is about testing, we're reading a previously captured .pcap file
captureFile = Config.get('testing', 'file')
pkts = PcapReader(captureFile)

# For each packet in the pcap file, extract, decode and print AppFlow IPFIX records.
for p in pkts:
    # assume layer 2 is Ethernet
    l3type = unpack(">H", p[12:14])[0]
    if l3type != 0x800:  # not IP
        debugLogger.info("DISCARD: Non-IP Packet")
        continue

    pos = 14  # Ethernet length
    tmp = ord(p[pos])
    ip_version = tmp >> 4
    ip_hdr_len = (tmp & 0x0F) << 2
    l4type = ord(p[pos + 9])
    if ip_version != 4 or l4type != 17:  # not ipv4 or UDP
        debugLogger.info("DISCARD: Non-IP4 Packet (or non-UDP packet")
        continue

    pos += ip_hdr_len
    src_port, dst_port, udp_len = unpack(">HHH", p[pos:pos + 6])
    data = p[pos + 8:]
    if len(data) != udp_len - 8:  # data length does not equal length in UDP header
        debugLogger.info("DISCARD: bad length UDP packet (header: {0}, actual: {1}".format(udp_len, len(data)))
        continue

    if dst_port == PORT:
        addr = ['unknown', src_port]
        ipfix = Parser(data, addr, logger=debugLogger)
        if ipfix.data:
            splunkLogger.info(str(ipfix))

    else:
        debugLogger.info("DISCARD: Data to wrong port {0} observer='{1}' data='{2}'".format(dst_port, src_port, data.encode('hex')))
