package edu.jduan8.pcaparser;

import java.util.Arrays;

public final class IPv4 implements IPacket {
    private final static int[] offset = {0, 1, 2, 4, 6, 8, 9, 10, 12, 16};
    private final static int[] length = {1, 1, 2, 2, 2, 1, 1, 2, 4, 4};
    private byte[] data_buf;
    private int start;
    private IPacket nextLayer;

    IPv4(byte[] __buf, int __start) {
        assert(__buf != null);
        data_buf = __buf;
        start = __start;
    }

    private void link() {
        int type = data_buf[start + 9];
        switch (type) {
            case 0x01:        /* IPv4 protocol */
                nextLayer = new ICMP(data_buf, start + 20);
                break;
            case 0x06:        /* IPv6 protocol */
                nextLayer = new TCP(data_buf, start + 20);
                break;
            case 0x11:        /* address resolution protocol */
                nextLayer = new UDP(data_buf, start + 20);
                break;
        }
    }

    public byte[] field(String field) {
        int i;
        switch (field) {
            case "verlen":  /* 1, version << 4 | header length >> 2 */
                i = 0;
                break;
            case "tos":     /* 1, type of service */
                i = 1;
                break;
            case "len":     /* 2, total length */
                i = 2;
                break;
            case "id":      /* 2, identification */
                i = 3;
                break;
            case "offset":  /* 2, fragment offset field */
                i = 4;
                break;
            case "ttl":     /* 1, time to live */
                i = 5;
                break;
            case "proto":   /* 1, protocol */
                i = 6;
                break;
            case "cksm":    /* 2, checksum */
                i = 7;
                break;
            case "src":     /* 4, source address */
                i = 8;
                break;
            case "dst":     /* 4, dest address */
                i = 9;
                break;
            default:
                return null;
        }
        return Arrays.copyOfRange(data_buf, start+offset[i], start+offset[i]+length[i]);
    }

    public String type() {
        return "I";
    }

    public IPacket next() {
        return nextLayer;
    }

}
