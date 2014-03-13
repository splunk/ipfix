#!/usr/bin/env python
__author__ = 'Joel Bennett'
from struct import unpack
import logging
from IPFIXData import *


class Parser:
    templates = None

    def __init__(self, rawData, address, logger=logging):
        self.source = address
        self.data = []
        setStart = 16  # header size
        (self.version, self.length, self.timestamp, self.sequence, self.observerId) = unpack("!HHIII",
                                                                                             rawData[:setStart])
        self.templateKey = str(address[0]), str(address[1]), str(self.observerId)

        while setStart < self.length:
            (setId, setLength) = unpack("!HH", rawData[setStart:setStart + 4])
            logger.info(
                "Version: {}; FullLength: {}; Timestamp: {}; FlowSequence: {}; ObserverDomainId: {}; Address: {}; FlowSetId: {}; FlowSetLength: {}; ".format(
                    self.version, self.length, self.timestamp, self.sequence, self.observerId, self.source, setId, setLength))

            if setId == 2:
                TemplateSet(self.templateKey, rawData[setStart + 4:setStart + setLength], logger=logger)
                ## For debugging, collect a few templates in the error logs:
                #logger.info("<IPFIXTemplate length='{length}' address='{address}:{port}' observer='{observer}'>{data}</IPFIXTemplate>".format(
                #    address = address[0], port = address[1], observer = self.observerId, length = setLength-4,
                #    data = rawData[setStart+4:setStart+setLength].encode('hex')))

            if setId == 3:
                OptionTemplateSet(self.templateKey, rawData[setStart + 4:setStart + setLength], logger=logger)
                ## For debugging, collect a few templates in the error logs:
                #logger.info("<IPFIXOption length='{length}' address='{address}:{port}' observer='{observer}'>{data}</IPFIXOption>".format(
                #    address = address[0], port = address[1], observer = self.observerId, length = setLength-4,
                #    data = rawData[setStart+4:setStart+setLength].encode('hex')))

            # If setId > 255, that means it's a Data Set Record
            if setId > 255:
                # Need to wrap IPFIXDataSet in [] to ensure it doesn't unroll,
                # This way we end up with .data being an array of sets
                self.data += [DataSet(self.templateKey, self.sequence, setId, self.timestamp, rawData[setStart + 4: setStart + setLength], logger=logger)]
                ## For debugging, collect a few records in the error logs:
                # logger.info("<IPFIXData length='{length}' address='{address}:{port}' observer='{observer}'>{data}</IPFIXData>".format(
                #     address=address[0], port=address[1], observer=self.observerId, length=setLength - 4,
                #     data=rawData[setStart: setStart + setLength].encode('hex')))

            setStart += setLength

    def __str__(self):
        # return "Version: {}; Length: {}; FlowSequence: {}; Data Records:\n".format(self.version, self.length, self.sequence) + str([str(dataSet) for dataSet in self.data])
        return "\n".join([str(dataSet) for dataSet in self.data])
