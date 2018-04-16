package com.jduan.pcaparser;


/* https://wiki.wireshark.org/Development/LibpcapFileFormat#Record_.28Packet.29_Header */
abstract class PktHdr implements Packet {
    private final static int TS_SEC = -1;       /* 4, timestamps seconds */
    private final static int TS_USEC = -2;      /* 4, timestamps microseconds */
    private final static int INCL_LEN = -3;     /* 4, actual length of packet */
    private final static int ORIG_LEN = -4;     /* 4, total length of packet */
    private final static int PKTHDR_LEN = 16;

    private byte[] pktHdr_buf;

    PktHdr() {
        assert(Pcap.reader != null);
        pktHdr_buf = new byte[PKTHDR_LEN];
        Pcap.reader.fill(pktHdr_buf);
    }

    int getDataLen() {
        return Utils.bytes2Int(pktHdr_buf, 12) & 0xFFFF;
    }

    public String field(int field) {
        switch (field) {
            case TS_SEC:
                return Integer.toString(Utils.bytes2Int(pktHdr_buf, 0));
            case TS_USEC:
                return Integer.toString(Utils.bytes2Int(pktHdr_buf, 4));
            case INCL_LEN:
                return Integer.toString(Utils.bytes2Int(pktHdr_buf, 8));
            case ORIG_LEN:
                return Integer.toString(Utils.bytes2Int(pktHdr_buf, 12));
            default:
                return null;
        }
    }

    public String type() {
        return "Packet Header";
    }

    public void print() {
        System.out.printf("Packet Header: ts:%d, ts_us:%d, caplen:%d, len:%d\n\n",
                Utils.bytes2Int(pktHdr_buf, 0),
                Utils.bytes2Int(pktHdr_buf, 4),
                Utils.bytes2Int(pktHdr_buf, 8),
                Utils.bytes2Int(pktHdr_buf, 12)
        );
    }
}

