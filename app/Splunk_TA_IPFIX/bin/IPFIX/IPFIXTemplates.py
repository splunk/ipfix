#!/usr/bin/env python
__author__ = 'Joel Bennett'
from struct import unpack
from os import path, walk, environ, getpid
from IPFIX import TEMPLATE_PATH

import xml.etree.cElementTree as ElementTree
import logging
import traceback

class DataType:
    def __init__(self, id, name, unpackCode, defaultLength):
        self.id = id
        self.name = name
        self.unpackCode = unpackCode
        self.defaultLength = defaultLength


class TemplateField:
    elements = {}
    dataTypes = [
        DataType(0, 'octetArray', 's', 1),
        DataType(1, 'unsigned8', 'B', 1),
        DataType(2, 'unsigned16', 'H', 2),
        DataType(3, 'unsigned32', 'L', 4),
        DataType(4, 'unsigned64', 'Q', 8),
        DataType(5, 'signed8', 'b', 1),
        DataType(6, 'signed16', 'h', 2),
        DataType(7, 'signed32', 'l', 4),
        DataType(8, 'signed64', 'q', 8),
        DataType(9, 'float32', 'f', 4),
        DataType(10, 'float64', 'd', 8),
        DataType(11, 'boolean', '?', 1),
        DataType(12, 'macAddress', '6B', 6),
        DataType(13, 'string', 's', 65535),
        DataType(14, 'dateTimeSeconds', 'I', 4),
        DataType(15, 'dateTimeMilliseconds', 'Q', 8),
        DataType(16, 'dateTimeMicroseconds', 'Q', 8),
        DataType(17, 'dateTimeNanoseconds', 'Q', 8),
        DataType(18, 'ipv4Address', '4B', 4),
        DataType(19, 'ipv6Address', '16B', 16),
        None,  # TODO: IPFIXDataType(20,'basicList','B',65535),
        None,  # TODO: IPFIXDataType(21,'subTemplateList','B',65535),
        None,  # TODO: IPFIXDataType(22,'subTemplateMultiList','B',65535)
    ]

    def __init__(self, elementId, enterpriseId=0, length=0, name=None, dataTypeName=None, dataTypeSemantics=None,
                 isScopeField=False):
        self.id = elementId
        self.enterpriseId = enterpriseId
        self.isScopeField = isScopeField
        self.length = length
        self.name = name
        self.dataType = None
        self.dataTypeName = dataTypeName
        self.dataTypeSemantics = dataTypeSemantics

        key = "{}:{}".format(enterpriseId, elementId)

        if dataTypeName:
        ## Find the actual dataType object
            for t in TemplateField.dataTypes:
                if t and t.name == dataTypeName:
                    self.dataType = t
                    break

        if name:
            TemplateField.elements[key] = self
        elif key in TemplateField.elements:
            record = TemplateField.elements[key]
            self.name = record.name
            self.dataTypeName = record.dataTypeName
            self.dataType = record.dataType
            self.dataTypeSemantics = record.dataTypeSemantics

    @classmethod
    def __getitem__(cls, item):
        return TemplateField.elements[item]

    def __str__(self):
        return "Id:{_.id}; Length:{_.length}; EnterpriseId:{_.enterpriseId}; DataType:{_.dataTypeName}; Name:{_.name};".format(_=self)

class Template(object):
    def __init__(self, rawData, logger=logging):
        self.id, self.fieldCount = unpack("!HH", rawData[0:4])
        self.fields = []
        self.length = 4
        # print "Template {}".format(self.id)
        # dataLen = len(data)
        for f in range(self.fieldCount):
            elementId, fieldLength = unpack("!HH", rawData[self.length:self.length + 4])
            enterpriseId = 0
            if elementId >> 15 == 1:
                elementId ^= 0b1000000000000000  # 0x8000 #
                (enterpriseId,) = unpack("!L", rawData[self.length + 4:self.length + 8])
                self.length += 8
            else:
                self.length += 4

            # logger.info("Field: {}:{} ({})".format(enterpriseId, elementId, fieldLength))
            self.fields.append(TemplateField(elementId, enterpriseId, fieldLength))

    def __len__(self):
        return sum([f.length if f.length < 65535 else 2 for f in self.fields])

    def __str__(self):
        return "Template {} with {} fields:\nId    Length Enterprise Type                 Name\n".format(self.id,
                                                                                                      self.fieldCount) + \
               "\n".join([
                   "{field.id:<5} {field.length:>6} {field.enterpriseId:<10} {field.dataTypeName:<20} {field.name}".format(
                       field=field)
                   for field in self.fields])

    def __getitem__(self, item):
        return self.fields[item]

    def __iter__(self):
        return self.fields.__iter__()


class MetaTemplateSet(type):
    _known_templates = {}

    def _get_known_templates(self):
        #for key in self._known_templates:
        #    print("Known templates {} - {} - {} - {}: {}".format(getpid(), id(self._known_templates), key, id(self._known_templates[key]), ", ".join([str(k) for k in self._known_templates[key]])))
        #print(traceback.format_stack())
        return self._known_templates

    def _set_known_templates(self, value):
        #print("Set known templates: {} = {}".format(id(self._known_templates), id(value)))
        #print(traceback.format_stack())
        self._known_templates = value

    knownTemplates = property(_get_known_templates, _set_known_templates)

class TemplateSet(object):
    __metaclass__ = MetaTemplateSet

    @staticmethod
    def getTemplateSafe(templateKey, templateId):
        key = ":".join(templateKey)
        if key in TemplateSet.knownTemplates:
            t = TemplateSet.knownTemplates[key]
            if templateId in t:
                return t[templateId]
        return None

    @staticmethod
    def getTemplate(templateKey, templateId):
        key = ":".join(templateKey)
        return TemplateSet.knownTemplates[key][templateId]

    @staticmethod
    def hasTemplate(templateKey, templateId):
        key = ":".join(templateKey)
        return key in TemplateSet.knownTemplates and templateId in TemplateSet.knownTemplates[key]

    def __init__(self, templateKey, rawData=None, logger=logging):
        self.templateKey = templateKey
        self.length = 0
        self.logger = logger

        key = ":".join(templateKey)

        ## Retrieve the templates we already know about (if there are any)
        if key in TemplateSet.knownTemplates:
            self.templates = TemplateSet.knownTemplates[key]
        else:
            self.templates = {}

        if rawData:
            self.length = len(rawData)

            _next = 0
            while _next < self.length:
                template = Template(rawData[_next:], logger=logger)
                logger.debug(str(template))
                self.templates[template.id] = template
                _next += template.length

        ## Store the templates we know about now!
        TemplateSet.knownTemplates[key] = self.templates

    def __iter__(self):
        return self.templates.values().__iter__()

    def __str__(self):
        return "Template Set from {} has {} templates:\n".format(self.templateKey, len(self.templates)) + \
               "\n\n".join([str(template) for template in self])


class OptionTemplate(Template):
    def __init__(self, rawData):
        # DO NOT call the super __init__ constructor ...
        super(OptionTemplate, self)  # .__init__(rawData)
        self.id, self.fieldCount, self.scopeCount = unpack("!HHH", rawData[0:6])
        self.fields = []
        self.length = 6
        self.nonScopeCount = self.fieldCount - self.scopeCount
        for f in range(self.fieldCount):
            elementId, fieldLength = unpack("!HH", rawData[self.length:self.length + 4])
            enterpriseId = 0
            if elementId >> 15 == 1:
                elementId ^= 0b1000000000000000  # 0x8000 #
                (enterpriseId,) = unpack("!L", rawData[self.length + 4:self.length + 8])
                self.length += 8
            else:
                self.length += 4

            # print "Field: ({}) {} {}".format(enterpriseId, elementId, fieldLength)
            # print "Option Field: ({}) {} {}".format(enterpriseId, elementId, fieldLength)
            self.fields.append(
                TemplateField(elementId, enterpriseId, fieldLength, isScopeField=(f > self.nonScopeCount)))

    def __len__(self):
        return sum([f.length if f.length < 65535 else 2 for f in self.fields])

    def __str__(self):
        return "OptionTemplate {} with {} fields:\nId    Length Enterprise Type                 Name\n".format(self.id, len(self.fields)) + \
               "\n".join([
                   "{field.id:<5} {field.length:>6} {field.enterpriseId:<10} {field.dataTypeName:<20} {field.name}".format(
                       field=field)
                   for field in self.fields])


class OptionTemplateSet(TemplateSet):
    def __init__(self, templateKey, rawData=None, logger=logging):
        # DO NOT call the super __init__ constructor ...
        super(OptionTemplateSet, self)  # .__init__(templateKey, rawData, logger)
        self.logger = logger
        self.length = 0
        key = ":".join(templateKey)
        if key in TemplateSet.knownTemplates:
            self.templates = TemplateSet.knownTemplates[key]
        else:
            self.templates = {}
        if rawData:
            self.length = len(rawData)

            _next = 0
            while _next < self.length:
                template = OptionTemplate(rawData[_next:])
                logger.info(str(template))
                self.templates[template.id] = template
                _next += template.length

        TemplateSet.knownTemplates[key] = self.templates

    def __iter__(self):
        return self.templates.values().__iter__()

    def __str__(self):
        return "OptionTemplate Set from {} has {} templates:\n".format(self.templateKey, len(self.templates)) + \
               "\n\n".join([str(template) for template in self])


def flatten(items, name=None):
    import collections

    for el in items:
        if isinstance(el, collections.Iterable) and not isinstance(el, basestring):
            for sub in flatten(el):
                if name is not None:
                    yield getattr(sub, name)
                else:
                    yield sub
        else:
            if name is not None:
                yield getattr(el, name)
            else:
                yield el

for root, dirs, files in walk(TEMPLATE_PATH):
    for filename in files:
        enterpriseId = 0
        name, ext = filename.split('.')
        if ext == 'xml':
            fileSource = path.join(TEMPLATE_PATH, filename)

            try:
                spec = ElementTree.parse(fileSource)
            except Exception, e:
                logging.error("Unable to parse XML for " + fileSource + ": " + str(e))
                continue

            if filename != "ipfix.xml":
                try:
                    registration_rule = spec.getroot().findtext(".//{http://www.iana.org/assignments}registry[@id='ipfix-information-elements']/{http://www.iana.org/assignments}registration_rule")
                    enterpriseId = int(registration_rule)
                except Exception, e:
                    try:
                        enterpriseId = int(path.split(path.splitext(filename)[0])[1])
                    except Exception, e:
                        enterpriseId = 0
                        pass
                    pass
            ## The ipfix might have lots of registries, the one we care about is the ipfix information elements registry
            records = spec.getroot().findall(
                ".//{http://www.iana.org/assignments}registry[@id='ipfix-information-elements']/{http://www.iana.org/assignments}record")
            ## Loop through all the records and insert them with the key = enterpiseId:elementId
            for record in records:
                TemplateField.elements[
                    "{}:{}".format(enterpriseId, record.findtext('{http://www.iana.org/assignments}elementId'))] = \
                    TemplateField(
                        elementId=record.findtext('{http://www.iana.org/assignments}elementId'),
                        enterpriseId=record.findtext('{http://www.iana.org/assignments}enterpriseId') or enterpriseId,
                        name=record.findtext('{http://www.iana.org/assignments}name'),
                        dataTypeName=record.findtext('{http://www.iana.org/assignments}dataType'),
                        dataTypeSemantics=record.findtext('{http://www.iana.org/assignments}dataTypeSemantics')
                    )


def test():
    templateKey = "192.168.0.12", "4089", "42"
    optionSets = [
        "01090004000100950004809600040000173f809700040000173f8098ffff0000173f".decode('hex'),
    ]

    templateSets = [
        "01000015008a00040090000400940008808100040000173f808500040000173f003c00010004000100d2000200080004000c000400070002000b0002000200080001000800060001808400080000173f009a0008009b0008000a0004000e0004809700040000173f01010016008a00040090000400940008808100040000173f808500040000173f003c00010004000100d2000200080004000c000400070002000b0002000200080001000800060001808400080000173f009a0008009b0008808000040000173f000e0004000a0004809700040000173f0102001b008a00040090000400940008808100040000173f808500040000173f003c00010004000100d2000200080004000c000400070002000b0002000200080001000800060001808400080000173f009a0008009b0008000a0004000e0004809700040000173f8082ffff0000173f8083ffff0000173f808cffff0000173f808dffff0000173f808effff0000173f808fffff0000173f01030015008a00040090000400940008808100040000173f808500040000173f003c00010004000100d20002001b0010001c001000070002000b0002000200080001000800060001808400080000173f009a0008009b0008000a0004000e0004809700040000173f01040016008a00040090000400940008808100040000173f808500040000173f003c00010004000100d20002001b0010001c001000070002000b0002000200080001000800060001808400080000173f009a0008009b0008808000040000173f000e0004000a0004809700040000173f0105001b008a00040090000400940008808100040000173f808500040000173f003c00010004000100d20002001b0010001c001000070002000b0002000200080001000800060001808400080000173f009a0008009b0008000a0004000e0004809700040000173f8082ffff0000173f8083ffff0000173f808cffff0000173f808dffff0000173f808effff0000173f808fffff0000173f01060019008a00040090000400940008808100040000173f808500040000173f003c00010004000100d2000200080004000c000400070002000b0002000200080001000800060001808400080000173f009a0008009b0008000a0004000e0004809000020000173f809100080000173f809200080000173f809300080000173f809700040000173f01070019008a00040090000400940008808100040000173f808500040000173f003c00010004000100d20002001b0010001c001000070002000b0002000200080001000800060001808400080000173f009a0008009b0008000a0004000e0004809000020000173f809100080000173f809200080000173f809300080000173f809700040000173f01080005808600010000173f00d2000100d20002808800040000173f8087ffff0000173f".decode(
            'hex'),
    ]

    print "Test Parsing Template Sets"
    for t in templateSets:
        # Parse the sets
        TemplateSet(templateKey, t)

    for t in optionSets:
        # Parse the sets
        OptionTemplateSet(templateKey, t)

    # Verify that we can lookup templates by address + observer id
    print TemplateSet(templateKey)

    templates = TemplateSet(templateKey)
    enterpriseIDs = set([])
    [map(enterpriseIDs.add, j) for j in [[f.id for f in t if f.enterpriseId] for t in templates]]
    print sorted(enterpriseIDs)
    print sorted([t.id for t in templates])


if __name__ == "__main__":
    test()
