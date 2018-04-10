package edu.jduan8.pcaparser;

import java.util.Arrays;


public class Packet implements IPacket {
    private final static int[] offset = {0, 4, 8, 12};
    private final static int[] length = {4, 4, 4, 4};
    private byte[] pktHdrBuf;

    Packet() {
        assert Pcap.reader != null;
        pktHdrBuf = new byte[16];
        Pcap.reader.fill(pktHdrBuf);
    }

    int getPktLen() {
        return Utils.byteArrayToInt(pktHdrBuf, 8);
    }

    public void link() {}

    public byte[] field(String field) {
        int i;
        switch (field) {
            case "ts_s":    /* 32, timestamps seconds */
                i = 0;
                break;
            case "ts_us":   /* 32, timestamps microseconds */
                i = 1;
                break;
            case "caplen":  /* 32, number of packets saved in file */
                i = 2;
                break;
            case "len":     /* 32, actual length of packet */
                i = 3;
                break;
            default:
                return null;
        }
        return Arrays.copyOfRange(pktHdrBuf, offset[i], offset[i]+length[i]);
    }

    public String type() {
        return "Packet Header";
    }

    public IPacket next() {
        // check
        return null;
    }
}
