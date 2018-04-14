package com.jduan.pcaparser;

import java.util.Arrays;


public class PcapHdr implements Packet {
    public final static int MAGIC = 1;      /* 32, magic number */
    public final static int V_MAJOR = 2;    /* 16, major version number */
    public final static int V_MINOR = 3;    /* 16, minor version number */
    public final static int THISZONE = 4;   /* 32, GMT */
    public final static int SIGFIGS = 5;    /* 32, accuracy of timestamps */
    public final static int SNAPLEN = 6;    /* 32, max length pf captured packets */
    public final static int LINKTYPE = 7;   /* 32, data line type */

    private final static int pcapHdr_len = 24;

    private byte[] pcapHdr_buf;

    PcapHdr() {
        pcapHdr_buf = new byte[pcapHdr_len];
        assert Pcap.reader != null;
        Pcap.reader.fill(pcapHdr_buf);
    }

    public String field(int id) {
        switch (id) {
            case MAGIC:
                return Integer.toString(Utils.byteArrayToInt(pcapHdr_buf, 0));
            case V_MAJOR:
                return Integer.toString(Utils.byteArrayToInt(pcapHdr_buf, 4));
            case V_MINOR:
                return Integer.toString(Utils.byteArrayToShort(pcapHdr_buf, 6));
            case THISZONE:
                return Integer.toString(Utils.byteArrayToInt(pcapHdr_buf, 8));
            case SIGFIGS:
                return Integer.toString(Utils.byteArrayToInt(pcapHdr_buf, 12));
            case SNAPLEN:
                return Integer.toString(Utils.byteArrayToInt(pcapHdr_buf, 16));
            case LINKTYPE:
                return Integer.toString(Utils.byteArrayToInt(pcapHdr_buf, 20));
            default:
                return null;
        }
    }

    int get_linktype() {
        return Utils.byteArrayToInt(pcapHdr_buf, 20);
    }

    public String type() {
        return "Pcap Header";
    }

    public Packet next() {
        return null;
    }
    
    public String text() {
        return String.format("Pcap Header: version:%d.%d, snaplen:%d",
                Utils.byteArrayToShort(pcapHdr_buf, 4),
                Utils.byteArrayToShort(pcapHdr_buf, 6),
                Utils.byteArrayToInt(pcapHdr_buf, 16)
        );
    }
    
    public void print() {
        System.out.println(text());
    }

    public void printAll() {
        print();
    }
}

