package com.jduan;

import java.util.Iterator;


/* https://en.wikipedia.org/wiki/Ethernet_frame */
public final class Ethernet extends Protocol {
    public final static int DHOST = 0;      /* 6, Destination host address */
    public final static int SHOST = 6;      /* 6, Source host address */
    public final static int ETH_TYPE = 12;  /* 2, Type of ethernet */

    private final static int ETH_LEN = 14;
    private PktHdr pktHdr;

    Ethernet() {
        pktHdr = new PktHdr();
        data_buf = new byte[pktHdr.getDataLen()];
        Pcap.reader.fill(data_buf);
        nextLayer = link();
    }

    private Protocol link() {
        int type = Utils.bBytes2Short(data_buf, 12) & 0xFFFF;
        switch (type) {
            case 0x0800:
                return new IPv4(data_buf, ETH_LEN);
            case 0x86DD:
                return new IPv6(data_buf, ETH_LEN);
            case 0x0806:
                return new ARP(data_buf, ETH_LEN);
            default:
                return null;
        }
    }

    public String field(int id) {
        switch (id) {
            case DHOST:
                return Utils.bytes2MAC(data_buf, 0);
            case SHOST:
                return Utils.bytes2MAC(data_buf, 6);
            case ETH_TYPE:
                return String.format("0x%04x", Utils.bBytes2Short(data_buf, 12));
            default:
                return pktHdr.field(id);
        }
    }

    public String type() {
        return "Ethernet";
    }

    public String text() {
        return String.format("Ethernet:\t SHOST:%s, DHOST:%s",
                field(Ethernet.SHOST),
                field(Ethernet.DHOST)
        );
    }

    public static void main(String[] args) {
        TEST.timer.start();
        Pcap pcap = new Pcap(TEST.getDir() + "eth.pcap");
        pcap.unpack();
        TEST.timer.end("Unpack");

        TEST.timer.start();
        Iterator<Protocol> iter = pcap.iterator();
        Protocol eth = iter.next();
        if (eth instanceof Ethernet) {
            System.out.println("DHOST: " + eth.field(Ethernet.DHOST));
            System.out.println("SHOST: " + eth.field(Ethernet.SHOST));
            System.out.println("ETH_TYPE: " + eth.field(Ethernet.ETH_TYPE));
        }
        TEST.timer.end("PRINT");
    }
}
