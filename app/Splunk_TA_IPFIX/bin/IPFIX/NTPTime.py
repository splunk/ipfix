import socket
import calendar
import datetime
from struct import unpack


def ntop(address_family, ipAddress):
    """
    This function is the equivalent of socket.inet_ntop.
    """
    if address_family == socket.AF_INET:
        data = ["%d" % (ord(a_char)) for a_char in ipAddress]
        ret_str = ".".join(data)
    else:  # socket.AF_INET6
        words = [(ord(ipAddress[cnt]) << 8) | ord(ipAddress[cnt + 1]) for cnt in xrange(0, 16, 2)]
        zeros = [index for index in xrange(0, 8) if words[index] == 0]
        begin_run = -1
        end_run = -1
        curr_value = -1
        for cnt, index in enumerate(zeros):
            if begin_run == -1 and cnt < len(zeros) - 1:
                if index + 1 == zeros[cnt + 1]:
                    begin_run = index
                curr_value = index
            else:
                if curr_value + 1 == index:
                    curr_value = index
                else:
                    end_run = index
        if end_run == -1 and begin_run != -1:
            end_run = curr_value
        if begin_run != -1:
            del words[begin_run:end_run]
            words[begin_run] = None
        str_words = ["%x" % a_word if a_word is not None else "" for a_word in words]
        ret_str = ":".join(str_words)
    return ret_str

# Windows does not support inet_ntop, so we need this try/except.
try:
    socket_inet_ntop = socket.inet_ntop
except AttributeError:
    socket_inet_ntop = ntop


class NtpTime:
    """
    NTP timestamp is represented as a 64-bit unsigned fixed-point number, in
    seconds relative to 0h on 1 Jan 1900. The integer part is in the first 32
    bits and the fraction part in the last 32 bits.
    """

    ## NOTE: the epoch rolls sometimes in Feb 8 2036, we'll need to update this by then!
    ntpEpoch = datetime.datetime(year=1900, month=1, day=1)

    def __init__(self, seconds, fraction, scale=1e6):
        self.seconds = seconds
        self.fraction = fraction

        fraction /= (scale / 1e6)  # Scale scale to microseconds
        self.dateTime = NtpTime.ntpEpoch + datetime.timedelta(
            seconds=seconds,
            microseconds=fraction
        )
        ## I'm leaving this here because it produces a different result, and I thought it was right, once:
        ## It's a matter of a second or so, if anyone can help me understand which is right.
        # self.dateTime = datetime.datetime.utcfromtimestamp( seconds + (float(fraction) / scale) - 2208988800 )
        # print self.dateTime.isoformat()

    def __str__(self):
        return self.dateTime.isoformat()

    def __float__(self):
        unixTime = calendar.timegm(self.dateTime.utctimetuple()) + (self.dateTime.microsecond / 1000000.0)
        return unixTime

    @staticmethod
    def fromBytes(rawData):
        seconds = unpack("!I", rawData[0:4])[0]
        if len(rawData) >= 8:
            fraction = unpack("!I", rawData[4:8])[0]
        else:
            fraction = 0
        return NtpTime(seconds, fraction)

    @staticmethod
    def fromLongLong(ntpTime):
        """
        NTP timestamp is represented as a 64-bit unsigned fixed-point number, in
        seconds relative to 0h on 1 Jan 1900. The integer part is in the first 32
        bits and the fraction part in the last 32 bits.
        """
        seconds = (ntpTime >> 32) & 0xFFFFFFFF
        fraction = (ntpTime & 0xFFFFFFFF)
        return NtpTime(seconds, fraction)
        ## Unix Epoch is 1 Jan 1970 (2208988800 seconds from NTP Epoch)
        # return seconds + (float(fraction) / scale) - 2208988800

    @staticmethod
    def convertNtpTimestampToUnixTimestamp(longLong, scale=1e10):
        """
        Don't use this legacy conversion.
        It unfortunately results in precision that was not there in the original data
        """
        seconds = (longLong >> 32) & 0xFFFFFFFF
        fraction = (longLong & 0xFFFFFFFF) / float(scale)
        unixTime = seconds + fraction - 2208988800  # offset (in sec) between Jan 1, 1990 and Jan 1, 1970
        return unixTime
