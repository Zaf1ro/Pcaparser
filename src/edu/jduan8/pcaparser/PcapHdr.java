package edu.jduan8.pcaparser;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;


public class PcapHdr implements IPacket {
    private final static int[] offset = {0, 4, 6, 8, 12, 16, 20};
    private final static int[] length = {4, 2, 2, 4, 4, 4, 4};
    private byte[] pcapHdrBuf;

    PcapHdr() {
        pcapHdrBuf = new byte[24];
        assert Pcap.reader != null;
        Pcap.reader.fill(pcapHdrBuf);
    }

    public byte[] field(String field) {
        int i;
        switch (field) {
            case "magic":       /* 32, magic number */
                i = 0;
                break;
            case "v_major":     /* 16, major version number */
                i = 1;
                break;
            case "v_minor":     /* 16, minor version number */
                i = 2;
                break;
            case "thiszone":    /* 32, GMT */
                i = 3;
                break;
            case "sigfigs":     /* 32, accuracy of timestamps */
                i = 4;
                break;
            case "snaplen":     /* 32, max length pf captured packets */
                i = 5;
                break;
            case "linktype":    /* 32, data line type */
                i = 6;
                break;
            default:
                return null;
        }
        return Arrays.copyOfRange(pcapHdrBuf, offset[i], offset[i]+length[i]);
    }

    public int get_linktype() {
        return Utils.byteArrayToInt(pcapHdrBuf, 6);
    }

    public void link() { /* do no-op */ }

    public String type() {
        return "Pcap Header";
    }

    public Packet next() {
        return null;
    }
}

