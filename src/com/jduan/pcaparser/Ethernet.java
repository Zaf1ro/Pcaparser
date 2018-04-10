package com.jduan.pcaparser;

import java.util.Arrays;


public final class Ethernet extends Packet {
    private final static int[] offset = {0, 6, 12};
    private final static int[] length = {6, 6, 2};
    private byte[] data_buf;
    private IPacket nextLayer;
    int len;                /* total byte of this packet */

    Ethernet() {
        super();
        this.len = super.getPktLen();
        data_buf = new byte[len];
        Pcap.reader.fill(data_buf);
        link();
        Pcap.packets.add(this);
    }

    public void link() {
        /* get the layer 2 protocol */
        int type = Utils.byteArrayToShort(data_buf, 14);
        switch (type) {
            case 0x0800:        /* IPv4 protocol */
                nextLayer = new IPv4(data_buf, 14);
                break;
//            case 0x0806:        /* IPv6 protocol */
//                nextLayer = new IPv6(data_buf, 14);
//                break;
//            case 0x86DD:        /* address resolution protocol */
//                nextLayer = new ARP(data_buf, 14);
//                break;
        }
    }

    public byte[] field(String field) {
        int i;
        switch (field) {
            case "dhost":       /* 6, Destination host address */
                i = 0;
                break;
            case "shost":       /* 6, Source host address */
                i = 1;
                break;
            case "eth_type":    /* 2, Type of ethernet */
                i = 2;
                break;
            default:
                return null;
        }
        return Arrays.copyOfRange(data_buf, offset[i], offset[i] + length[i]);
    }

    public String type() {
        return "Ethernet";
    }

    public IPacket next() {
        return nextLayer;
    }
}
