package com.jduan.pcaparser;

import java.util.Arrays;


abstract class PktHdr implements Packet {
    private final static int[] offset = {0, 4, 8, 12};
    private final static int[] length = {4, 4, 4, 4};
    private final static int pkt_len = 16;

    private byte[] pktHdr_buf;

    PktHdr() {
        assert(Pcap.reader != null);
        pktHdr_buf = new byte[pkt_len];
        Pcap.reader.fill(pktHdr_buf);
    }

    int getDataLen() {
        return Utils.bytes2Int(pktHdr_buf, 12);
    }

    public byte[] field(String field) {
        int i;
        switch (field) {
            case "ts_s":    /* 32, timestamps seconds */
                i = 0;
                break;
            case "ts_us":   /* 32, timestamps microseconds */
                i = 1;
                break;
            case "caplen":  /* 32, actual length of packet */
                i = 2;
                break;
            case "len":     /* 32, total length of packet */
                i = 3;
                break;
            default:
                return null;
        }
        return Arrays.copyOfRange(pktHdr_buf, offset[i], offset[i] + length[i]);
    }

    public String type() {
        return "Packet Header";
    }

    public Packet next() {
        // check
        return null;
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

