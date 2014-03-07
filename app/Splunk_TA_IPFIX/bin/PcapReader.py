from struct import unpack

# modified from scapy
class PcapReader:
    def __init__(self, filename):
        self.f = open(filename, "rb")
        magic = self.f.read(4)
        if magic == "\xa1\xb2\xc3\xd4":  # a big endian
            self.endian = ">"
        elif magic == "\xd4\xc3\xb2\xa1":  # a little endian
            self.endian = "<"
        else:
            raise Exception("Not a pcap capture file (bad magic):{0}".format(magic.encode('hex')))

        hdr = self.f.read(20)
        if len(hdr) < 20:
            raise Exception("Invalid pcap file (too short)")

        # assume layer2 is Ethernet
        #vermaj,vermin,tz,sig,snaplen,linktype = struct.unpack(self.endian+"HHIIII",hdr)
        #self.linktype = linktype

    def __iter__(self):
        return self

    def next(self):
        """implement the iterator protocol on a set of packets in a pcap file"""
        pkt = self.read_packet()
        if pkt is None:
            raise StopIteration
        return pkt

    def read_packet(self):
        """return a single packet read from the file

        returns None when no more packets are available
        """
        hdr = self.f.read(16)
        if len(hdr) < 16:
            return None
        sec, usec, caplen, wirelen = unpack(self.endian + "IIII", hdr)
        s = self.f.read(caplen)
        return s
        #return s,(sec,usec,wirelen) # caplen = len(s)

    def close(self):
        return self.f.close()
