from unittest import TestCase
from IPFIXParser import *

__author__ = 'JBennett'


class ParsingTests(TestCase):
    def setUp(self):
        self.logger = logging.getLogger('ipfix tests')
        self.logger.addHandler(logging.StreamHandler())
        #self.logger.setLevel("INFO")
        # self.templateKey = "192.168.0.12", "4089", "42"
        self.templateKey = '10.199.44.162', '52532', '2720843530'
        optionSets = [
            "01090004000100950004809600040000173f809700040000173f8098ffff0000173f".decode('hex'),
        ]

        templateSets = [
            "01000015008a00040090000400940008808100040000173f808500040000173f003c00010004000100d2000200080004000c000400070002000b0002000200080001000800060001808400080000173f009a0008009b0008000a0004000e0004809700040000173f01010016008a00040090000400940008808100040000173f808500040000173f003c00010004000100d2000200080004000c000400070002000b0002000200080001000800060001808400080000173f009a0008009b0008808000040000173f000e0004000a0004809700040000173f0102001b008a00040090000400940008808100040000173f808500040000173f003c00010004000100d2000200080004000c000400070002000b0002000200080001000800060001808400080000173f009a0008009b0008000a0004000e0004809700040000173f8082ffff0000173f8083ffff0000173f808cffff0000173f808dffff0000173f808effff0000173f808fffff0000173f01030015008a00040090000400940008808100040000173f808500040000173f003c00010004000100d20002001b0010001c001000070002000b0002000200080001000800060001808400080000173f009a0008009b0008000a0004000e0004809700040000173f01040016008a00040090000400940008808100040000173f808500040000173f003c00010004000100d20002001b0010001c001000070002000b0002000200080001000800060001808400080000173f009a0008009b0008808000040000173f000e0004000a0004809700040000173f0105001b008a00040090000400940008808100040000173f808500040000173f003c00010004000100d20002001b0010001c001000070002000b0002000200080001000800060001808400080000173f009a0008009b0008000a0004000e0004809700040000173f8082ffff0000173f8083ffff0000173f808cffff0000173f808dffff0000173f808effff0000173f808fffff0000173f01060019008a00040090000400940008808100040000173f808500040000173f003c00010004000100d2000200080004000c000400070002000b0002000200080001000800060001808400080000173f009a0008009b0008000a0004000e0004809000020000173f809100080000173f809200080000173f809300080000173f809700040000173f01070019008a00040090000400940008808100040000173f808500040000173f003c00010004000100d20002001b0010001c001000070002000b0002000200080001000800060001808400080000173f009a0008009b0008000a0004000e0004809000020000173f809100080000173f809200080000173f809300080000173f809700040000173f01080005808600010000173f00d2000100d20002808800040000173f8087ffff0000173f".decode(
                'hex'),
        ]

        for t in templateSets:
            # Parse the sets
            TemplateSet(self.templateKey, t)

        for t in optionSets:
            # Parse the sets
            OptionTemplateSet(self.templateKey, t)

    def test_ThereShouldBeTenTemplates(self):
        """There should be ten templates loaded in the setup"""
        self.assertEqual(len(TemplateSet(self.templateKey).templates), 10)

    def test_MultipleDataSets(self):
        """When parsing a packet with many sets, all of them should be parsed"""
        data = "000a05ad51b656f700000056a22cc70a0109001a0ac72ca2000000010000246007482e33323320000100010900200ac72ca200000001000024610d482e33323320457272726f72000100010900230ac72ca2000000010000246210482e33323320512e39333120434d44000100010900230ac72ca2000000010000246310482e33323320512e39333120494531000100010900230ac72ca2000000010000246410482e33323320512e39333120494532000100010900240ac72ca2000000010000246511482e33323320512e3933312055736572000100010900200ac72ca200000001000024660d482e333233205555205044550001000109001e0ac72ca200000001000024670b482e33323320426f6479000100010900250ac72ca2000000010000246812482e3332332044796e616d696320544350000100010900250ac72ca2000000010000246912482e3332332044796e616d6963205544500001000109001b0ac72ca200000001000024b8085349502f5254500001000109001c0ac72ca2000000010000251c09525453502f5254500001000109002a0ac72ca2000000010000264817476e7574656c6c6120436f6e74726f6c2028544350290001000109001c0ac72ca2000000010000264909476e7574656c6c61000100010900250ac72ca20000000100002710124943413a2049726f6e436f76652d636d64000100010900240ac72ca20000000100002711114943413a20324b382d57696e37783332000100010900210ac72ca200000001000027120e4943413a20326b382d57696e38000100010900240ac72ca20000000100002713114943413a20416c736163652d57696e370001000109001f0ac72ca200000001000027140c4943413a205844352d5850000100010900210ac72ca200000001000027150e4943413a204175646163697479000100010900210ac72ca200000001000027160e4943413a205844342d57696e37000100010900240ac72ca20000000100002717114943413a205844342d57696e37783634000100010900220ac72ca200000001000027180f4943413a205844342d56697374610001000109001f0ac72ca200000001000027190c4943413a205844342d58500001000109002c0ac72ca2000000010000271a194943413a2058656e4465736b746f70352d57696e377836340001000109002e0ac72ca2000000010000271b1b4943413a2058656e4465736b746f70352d57696e2d5669737461000100010900290ac72ca2000000010000271c164943413a2058656e4465736b352d57696e377833320001000109002b0ac72ca2000000010000271d184943413a2058656e4465736b746f70352d57696e2d5850000100010900240ac72ca2000000010000271e114943413a205844352d57696e37783634000100010900220ac72ca2000000010000271f0f4943413a205844352d5669737461000100010900240ac72ca20000000100002720114943413a205844352d57696e377833320001000109001b0ac72ca20000000100002721084943413a205850000100010900270ac72ca20000000100002722144943413a20416c736163652d57696e37783332000100010900270ac72ca20000000100002723144943413a20416c736163652d57696e377836340001000109001b0ac72ca20000000100002724084943413a2049450001000109002c0ac72ca20000000100002725194943413a20457863616c696275722d57696e377836342d310001000109002c0ac72ca20000000100002726194943413a20457863616c696275722d57696e377833322d310001000109002c0ac72ca20000000100002727194943413a204d6963726f736f667420576f72642032303130000100010900310ac72ca200000001000027281e4943413a205374617469632d457863616c696275722d57696e377833320001000109002c0ac72ca20000000100002729194943413a204d6963726f736f667420457863656c20323031000100".decode(
            'hex')
        addr = ['10.199.44.162', '52532']
        ipfix = Parser(data, addr, logger=self.logger)

        print str(ipfix)
        self.assertEqual(40, len(ipfix.data))

    def test_MultipleDataElements(self):
        """When parsing a set of many packets, all of them should be parsed"""
        data = "000a04c151b656f700000056a22cc70a010904b10ac72ca2000000010000246007482e33323320000ac72ca200000001000024610d482e33323320457272726f72000ac72ca2000000010000246210482e33323320512e39333120434d44000ac72ca2000000010000246310482e33323320512e39333120494531000ac72ca2000000010000246410482e33323320512e39333120494532000ac72ca2000000010000246511482e33323320512e3933312055736572000ac72ca200000001000024660d482e33323320555520504455000ac72ca200000001000024670b482e33323320426f6479000ac72ca2000000010000246812482e3332332044796e616d696320544350000ac72ca2000000010000246912482e3332332044796e616d696320554450000ac72ca200000001000024b8085349502f525450000ac72ca2000000010000251c09525453502f525450000ac72ca2000000010000264817476e7574656c6c6120436f6e74726f6c202854435029000ac72ca2000000010000264909476e7574656c6c61000ac72ca20000000100002710124943413a2049726f6e436f76652d636d64000ac72ca20000000100002711114943413a20324b382d57696e37783332000ac72ca200000001000027120e4943413a20326b382d57696e38000ac72ca20000000100002713114943413a20416c736163652d57696e37000ac72ca200000001000027140c4943413a205844352d5850000ac72ca200000001000027150e4943413a204175646163697479000ac72ca200000001000027160e4943413a205844342d57696e37000ac72ca20000000100002717114943413a205844342d57696e37783634000ac72ca200000001000027180f4943413a205844342d5669737461000ac72ca200000001000027190c4943413a205844342d5850000ac72ca2000000010000271a194943413a2058656e4465736b746f70352d57696e37783634000ac72ca2000000010000271b1b4943413a2058656e4465736b746f70352d57696e2d5669737461000ac72ca2000000010000271c164943413a2058656e4465736b352d57696e37783332000ac72ca2000000010000271d184943413a2058656e4465736b746f70352d57696e2d5850000ac72ca2000000010000271e114943413a205844352d57696e37783634000ac72ca2000000010000271f0f4943413a205844352d5669737461000ac72ca20000000100002720114943413a205844352d57696e37783332000ac72ca20000000100002721084943413a205850000ac72ca20000000100002722144943413a20416c736163652d57696e37783332000ac72ca20000000100002723144943413a20416c736163652d57696e37783634000ac72ca20000000100002724084943413a204945000ac72ca20000000100002725194943413a20457863616c696275722d57696e377836342d31000ac72ca20000000100002726194943413a20457863616c696275722d57696e377833322d31000ac72ca20000000100002727194943413a204d6963726f736f667420576f72642032303130000ac72ca200000001000027281e4943413a205374617469632d457863616c696275722d57696e37783332000ac72ca20000000100002729194943413a204d6963726f736f667420457863656c2032303100".decode(
            'hex')
        addr = ['10.199.44.162', '52532']
        ipfix = Parser(data, addr, logger=self.logger)

        sets = 0
        records = 0
        for _set in ipfix.data:
            sets += 1
            print str(_set)
            for item in _set:
                print str(item)
                records += 1

        self.assertEqual(1, sets)
        self.assertEqual(40, records)

    def test_CanParseDataWithTemplates(self):
        """Test Parsing the data with the templates"""
        data = [
            # [264, "860000005065c43de5202062642d6e737670782d303120302d5050452d30203a2054435020434f4e4e5f5445524d494e415445203330303538352030203a2020536f757263652031302e3136302e3230332e32313a333839202d2044657374696e6174696f6e2031302e3136302e3230332e3234303a3338333930202d2053746172742054696d652032382f30392f323031323a31353a33373a333320474d54202d20456e642054696d652032382f30392f323031323a31353a33373a333320474d54202d20546f74616c5f62797465735f73656e642030202d20546f74616c5f62797465735f72656376203120".decode("hex")],
            # [265, "0000000000000005000023110d62642d6465766964782d3031000000000000000005000023021362645f73706c6b6465765f30325f38353134000000000000000005000022fd1362645f73706c6b6465765f30315f3835313400".decode('hex')],
            # [258, "00000001000000000000000000ab100300177f9c00ab1003040600000aa015dd0aa0cbf3b8a201bb0000000000000002000000000000006b19000000001d002000d420a8ee00075888d420a8ee0007588800000001800000030000241a00000000000000000000000000000000000000000100010001000100010001000100010001000100".decode('hex')],
            [258, "00000001000000000000000000ab119b00177fce00ab119b040600000aa015de0aa0cbf3ca2401bb0000000000000004000000000000015618000000001d002000d420a9171a5f0b80d420a9170004e7bb00000001800000030000241a0000000000000000000000000000000000000000022f00010001000447455400010001000100010001000100".decode('hex')],
            # [257, "00000001000000000000000000ab100400177f9c00ab1003040600000aa0cbf30aa015dd01bbb8a20000000000000007000000000000029b190000000041002000d420a8ee0006a4dfd420a8ee0008e6ec000000fc00000001800000030000241a".decode('hex')],
        ]
        ## If you want to see the parsing verbose data, you need to uncomment the setLevel("INFO")
        ## when doing so, comment out all but one packet above, or they'll come out all out of order
        # logger.setLevel("INFO")

        results = [
            DataSet(self.templateKey, d[0], datetime.datetime.utcnow().isoformat(), d[1], logger=self.logger) for d
            in data]
        for r in results:
            print r

        self.assertEqual(len(results), len(data))

        for r in results:
            if r.templateId == 265:
                twoSixFive = [d for d in r]
                self.assertEqual(len(twoSixFive), 3)

    def test_CanDecodeNtpTime(self):
        data = 'd420b0e20003ec1f'.decode('hex')
        time = NtpTime.fromBytes(data)
        self.assertEqual('2012-10-11T02:43:46.257055', str(time))

    def test_CanDecodeNtpTimeAsUnixTimestamp(self):
        data = 'd420b0e20003ec1f'.decode('hex')
        nTime = float(NtpTime.fromBytes(data))
        uTime = NtpTime.convertNtpTimestampToUnixTimestamp(unpack("!Q", data)[0], 1e6)
        # I can't for the life of me figure out why when I format as a string ...
        # They both have the same precision, and are equal
        self.assertEqual("{0:20f}".format(uTime), "{0:20f}".format(nTime))
        # But if I don't, this will fail if I set places = 7 or more
        self.assertAlmostEqual(uTime, nTime, places=6)
        # And this would fail too
        # self.assertTrue(uTime == nTime)

    def test_CanDecodeINET4Address(self):
        self.assertEqual('10.0.113.230', ntop(socket.AF_INET, '\x0a\x00\x71\xe6'))
        self.assertEqual('10.160.21.221', ntop(socket.AF_INET, '0aa015dd'.decode('hex')))

    def test_ParseCitrixData(self):
        """Test Parsing the data with the templates"""
        data = [
            [265, "0ac72ca2000000010000246007482e33323320000100".decode('hex')],
            [265, "0ac72ca200000001000024610d482e33323320457272726f72000100".decode('hex')],
            [265, "0ac72ca2000000010000246210482e33323320512e39333120434d44000100".decode('hex')],
            [265, "0ac72ca2000000010000246310482e33323320512e39333120494531000100".decode('hex')],
            [265, "0ac72ca2000000010000246410482e33323320512e39333120494532000100".decode('hex')],
            [265, "0ac72ca2000000010000246511482e33323320512e3933312055736572000100".decode('hex')],
            [265, "0ac72ca200000001000024660d482e33323320555520504455000100".decode('hex')],
            [265, "0ac72ca200000001000024670b482e33323320426f6479000100".decode('hex')],
            [265, "0ac72ca2000000010000246812482e3332332044796e616d696320544350000100".decode('hex')],
            [265, "0ac72ca2000000010000246912482e3332332044796e616d696320554450000100".decode('hex')],
            [265, "0ac72ca200000001000024b8085349502f525450000100".decode('hex')],
            [265, "0ac72ca2000000010000251c09525453502f525450000100".decode('hex')],
            [265, "0ac72ca2000000010000264817476e7574656c6c6120436f6e74726f6c202854435029000100".decode('hex')],
            [265, "0ac72ca2000000010000264909476e7574656c6c61000100".decode('hex')],
            [265, "0ac72ca20000000100002710124943413a2049726f6e436f76652d636d64000100".decode('hex')],
            [265, "0ac72ca20000000100002711114943413a20324b382d57696e37783332000100".decode('hex')],
            [265, "0ac72ca200000001000027120e4943413a20326b382d57696e38000100".decode('hex')],
            [265, "0ac72ca20000000100002713114943413a20416c736163652d57696e37000100".decode('hex')],
            [265, "0ac72ca200000001000027140c4943413a205844352d5850000100".decode('hex')],
            [265, "0ac72ca200000001000027150e4943413a204175646163697479000100".decode('hex')],
            [265, "0ac72ca200000001000027160e4943413a205844342d57696e37000100".decode('hex')],
            [265, "0ac72ca20000000100002717114943413a205844342d57696e37783634000100".decode('hex')],
            [265, "0ac72ca200000001000027180f4943413a205844342d5669737461000100".decode('hex')],
            [265, "0ac72ca200000001000027190c4943413a205844342d5850000100".decode('hex')],
            [265, "0ac72ca2000000010000271a194943413a2058656e4465736b746f70352d57696e37783634000100".decode('hex')],
            [265, "0ac72ca2000000010000271b1b4943413a2058656e4465736b746f70352d57696e2d5669737461000100".decode('hex')],
            [265, "0ac72ca2000000010000271c164943413a2058656e4465736b352d57696e37783332000100".decode('hex')],
            [265, "0ac72ca2000000010000271d184943413a2058656e4465736b746f70352d57696e2d5850000100".decode('hex')],
            [265, "0ac72ca2000000010000271e114943413a205844352d57696e37783634000100".decode('hex')],
            [265, "0ac72ca2000000010000271f0f4943413a205844352d5669737461000100".decode('hex')],
            [265, "0ac72ca20000000100002720114943413a205844352d57696e37783332000100".decode('hex')],
            [265, "0ac72ca20000000100002721084943413a205850000100".decode('hex')],
            [265, "0ac72ca20000000100002722144943413a20416c736163652d57696e37783332000100".decode('hex')],
            [265, "0ac72ca20000000100002723144943413a20416c736163652d57696e37783634000100".decode('hex')],
            [265, "0ac72ca20000000100002724084943413a204945000100".decode('hex')],
            [265, "0ac72ca20000000100002725194943413a20457863616c696275722d57696e377836342d31000100".decode('hex')],
            [265, "0ac72ca20000000100002726194943413a20457863616c696275722d57696e377833322d31000100".decode('hex')],
            [265, "0ac72ca20000000100002727194943413a204d6963726f736f667420576f72642032303130000100".decode('hex')],
            [265, "0ac72ca200000001000027281e4943413a205374617469632d457863616c696275722d57696e37783332000100".decode('hex')],
            [265, "0ac72ca20000000100002729194943413a204d6963726f736f667420457863656c20323031000100".decode('hex')],
        ]

        ## If you want to see the parsing verbose data, you need to uncomment the setLevel("INFO")
        ## when doing so, comment out all but one packet above, or they'll come out all out of order
        # logger.setLevel("INFO")

        results = [DataSet(
            self.templateKey,
            d[0],
            datetime.datetime.utcnow().isoformat(),
            d[1],
            logger=self.logger) for d in data]

        self.assertEqual(len(results), len(data))
