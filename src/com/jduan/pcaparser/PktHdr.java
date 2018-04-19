package com.jduan.pcaparser;


/* https://wiki.wireshark.org/Development/LibpcapFileFormat#Record_.28Packet.29_Header */
class PktHdr extends Protocol {
    public final static int TS_SEC = -1;       /* 4, timestamps seconds */
    public final static int TS_USEC = -2;      /* 4, timestamps microseconds */
    public final static int INCL_LEN = -3;     /* 4, actual length of packet */
    public final static int ORIG_LEN = -4;     /* 4, total length of packet */

    private final static int PKTHDR_LEN = 16;

    PktHdr() {
        assert (Pcap.reader != null);
        data_buf = new byte[PKTHDR_LEN];
        Pcap.reader.fill(data_buf);
    }

    int getDataLen() {
        return Utils.lBytes2Int(data_buf, 12);
    }

    public String field(int field) {
        switch (field) {
            case TS_SEC:
                return Integer.toString(Utils.bBytes2Int(data_buf, 0));
            case TS_USEC:
                return Integer.toString(Utils.bBytes2Int(data_buf, 4));
            case INCL_LEN:
                return Integer.toString(Utils.bBytes2Int(data_buf, 8));
            case ORIG_LEN:
                return Integer.toString(Utils.bBytes2Int(data_buf, 12));
            default:
                return null;
        }
    }

    public String type() {
        return "Protocol Header";
    }

    public String text() {
        return String.format("Protocol Header: ts:%s, ts_us:%s, caplen:%s",
                field(PktHdr.TS_SEC),
                field(PktHdr.TS_USEC),
                field(PktHdr.INCL_LEN)
        );
    }
}

