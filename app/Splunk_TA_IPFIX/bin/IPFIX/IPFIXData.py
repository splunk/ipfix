#!/usr/bin/env python
__author__ = 'Joel Bennett'
from struct import unpack
import datetime
import logging
from IPFIXTemplates import *
from NTPTime import *


class DataField:
    def __init__(self, name, value):
        self.name = name
        self.value = value if name != 'paddingOctets' else len(value)

        ## Escape quotes:
        if isinstance(self.value, basestring):
            self.value = self.value.replace('"', "'")

    def __str__(self):
        ## NOTE: uncomment the "if" to have paddingOctects render as empty strings
        if isinstance(self.value, float):
            return '{0}="{1:9f}"'.format(self.name, self.value)  # if self.name != 'paddingOctets' else ''
        else:
            return '{}="{}"'.format(self.name, self.value)  # if self.name != 'paddingOctets' else ''


class Data:
    @staticmethod
    def readVariableLengthString(data):
        """
        If the length of the Information Element is greater than or equal to
        255 octets, the length is encoded into 3 octets before the
        Information Element. The first octet is 255, and the length is
        carried in the second and third octets.
        """
        length = ord(data[0])
        if length == 255:
            length = unpack("!H", data[1:3])[0]
            start = 3
        else:
            start = 1
        data = data[start:length + start]
        return str(data).rstrip("\x00"), length + start, length

    def __init__(self, template, rawData, logger=logging):
        start = 0
        self.templateId = template.id
        self.data = []  # [IPFIXDataField('template', template.id)]
        for field in template:
            length = field.length

            if not field.dataType:
                #    The Collecting Process MUST note the Information Element identifier
                #    of any Information Element that it does not understand and MAY
                #    discard that Information Element from the Flow Record.
                # NOTE: we only parse variable-length strings, because those are identifiable by the length == 65535
                #       but we do not discard anything anymore. we display it as hex below...
                logger.warning(
                    "Have not implemented parsing for '{}' of length {} ({}:{}) which is needed for template {}.".format(
                        field.dataTypeName, field.length, field.enterpriseId, field.id, template.id))

            try:
                if field.length == 65535:
                    data, length, stringlength = self.readVariableLengthString(rawData[start:])
                    # Tweak start and length purely for pretty-print purposes
                    start += length - stringlength
                    length = stringlength
                else:
                    if not field.dataType:
                        self.data.append(DataField("{}:{}".format(field.enterpriseId, field.id), rawData[start:start + length].encode('hex')))
                        start += length
                        continue

                    code = "!" + (field.dataType.unpackCode
                                  if length == field.dataType.defaultLength
                                  else "L" if (field.dataType.unpackCode == 'Q' and length == 4)
                                  else str(length) + field.dataType.unpackCode)

                    if field.dataTypeName == 'dateTimeSeconds':
                        # MUST be encoded in a 32-bit integer
                        # containing the number of seconds since 0000 UTC Jan 1, 1970.
                        # The 32-bit integer allows the time encoding up to 136 years.
                        data = unpack(code, rawData[start:start + field.length])[0]
                        data = datetime.datetime.fromtimestamp(data).isoformat()

                    elif field.dataTypeName == 'dateTimeMilliseconds':
                        # MUST be encoded in a 64-bit integer
                        # containing the number of milliseconds since 0000 UTC Jan 1, 1970
                        data = unpack(code, rawData[start:start + field.length])[0]
                        data = datetime.datetime.fromtimestamp(data / 1000.0).isoformat()

                    elif field.dataTypeName.startswith('dateTime'):
                        # dateTimeMicroseconds and dateTimeNanoseconds are encoded as NTP timestamp
                        # Which is a 64 bit fixed-width with near picosecond precision
                        # But we're converting them to dateTime (with microsecond precision)
                        # and then rendering them as a float in unix timestamp
                        # Which is a float (and we're doing this at microsecond precision)
                        data = float(NtpTime.fromBytes(rawData[start:start + field.length]))
                    elif field.dataTypeName == 'ipv4Address':
                        data = socket_inet_ntop(socket.AF_INET, rawData[start:start + field.length])
                    elif field.dataTypeName == 'ipv6Address':
                        #data = unpack(code, rawData[start:start+field.length])[0]
                        data = socket_inet_ntop(socket.AF_INET6, rawData[start:start + field.length])
                    else:
                        data = unpack(code, rawData[start:start + field.length])[0]

                logger.info(
                    "Parsed {} ({}:{}) [ElementId: {}:{}] for template {}. Got '{}' from the data ({}): {}".format(
                        field.name, field.dataTypeName, length, field.enterpriseId, field.id, template.id, data,
                        code, rawData[start:start + length].encode('hex')))

            except Exception, err:
                data = "--"
                logger.error("EXCEPTION parsing {} ({}:{}) [ElementId: {}:{}] for template {}: {}. Data({}): {}".format(
                    field.name, field.dataTypeName, field.length, field.enterpriseId, field.id, template.id, err, code,
                    rawData[start:start + field.length].encode('hex')))

            self.data.append(DataField(field.name, data))
            # print "{} ({}): '{}' [{}:{}]".format(field.name, field.dataTypeName, code, start, start+length)
            start += length
        self.length = start
        # print "RECORD: {}".format(self)

    def __str__(self):
        ## NOTE: paddingOctets are currently NOT rendered at all
        return "; ".join([str(field) for field in self.data if field.name != 'paddingOctets'])


class DataSet:
    def __init__(self, templateKey, templateId, timestamp, rawData, logger=logging):
        self.templateKey = templateKey
        self.templateId = templateId
        self.logger = logger
        self.template = TemplateSet.getTemplateSafe(templateKey, templateId)

        self.timestamp = timestamp
        self.recordStart = 0
        self.data = rawData
        self.length = 0
        self.minRecordSize = 0
        if not self.template:
            # TODO: in UDP mode we should store this data until we do get the template
            logger.warn(
                "{}: Can't parse data set with Template ID: {} and Template Key: {} without a template. Data: {}".format(
                    timestamp, templateId, templateKey, rawData.encode("hex")))
        else:
            self.length = len(rawData)
            self.minRecordSize = len(self.template)

    def __iter__(self):
        self.recordStart = 0
        return self

    def next(self):
        if not self.template:
            self.template = TemplateSet.getTemplateSafe(self.templateKey, self.templateId)

            if not self.template:
                self.logger.warn(
                    "Still can't parse data set from {} with Template ID: {} and Template Key: {} without a template. Iteration Cancelled".format(
                        self.timestamp, self.templateId, self.templateKey))
                raise StopIteration
            else:
                self.length = len(self.data)
                self.minRecordSize = len(self.template)

        # self.logger.warn("Parsing data set from {} with Template ID: {} and Template Key: {} with template: \n {}".format(self.timestamp, self.templateId, self.templateKey, self.template))
        # self.logger.warn("Start: {}  Length: {}  MinRecordSize: {}".format(self.recordStart, self.minRecordSize, self.length))
        if self.recordStart + self.minRecordSize > self.length:
            raise StopIteration
            # print "Template: " + str(self.template)
        data = Data(self.template, self.data[self.recordStart:], self.logger)
        self.recordStart += data.length
        return data

    def __str__(self):
        header = 'TimeStamp="{}"; Template="{}"; Observer="{}"; Address="{}"; Port="{}"; '.format(self.timestamp,
                                                                                                  self.templateId,
                                                                                                  self.templateKey[2],
                                                                                                  self.templateKey[0],
                                                                                                  self.templateKey[1])
        if self.length:
            return header + (";\n" + header).join([str(data) for data in self]) + ";"
        else:
            return header + 'ParseError="Template not known (yet).";'
