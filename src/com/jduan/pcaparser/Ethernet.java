package com.jduan.pcaparser;


/* https://en.wikipedia.org/wiki/Ethernet_frame */
public final class Ethernet extends PktHdr {
    public final static int DHOST = 0;      /* 6, Destination host address */
    public final static int SHOST = 6;      /* 6, Source host address */
    public final static int ETH_TYPE = 12;  /* 2, Type of ethernet */

    private final static int ETH_LEN = 14;

    private byte[] data_buf;
    private Packet nextLayer;

    Ethernet() {
        super();
        data_buf = new byte[getDataLen()];
        Pcap.reader.fill(data_buf);
        nextLayer = link();
    }

    private Packet link() {
        /* get the layer 2 protocol */
        int type = Utils.bytes2Short(data_buf, 12) & 0xFFFF;
        switch (type) {
            case 0x0800:        /* IPv4 protocol */
                return new IPv4(data_buf, ETH_LEN);
            case 0x86DD:        /* IPv6 protocol */
                return new IPv6(data_buf, ETH_LEN);
            case 0x0806:        /* address resolution protocol */
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
                return Short.toString(Utils.bytes2Short(data_buf, 12));
            default:
                return null;
        }
    }

    public String type() {
        return "Ethernet";
    }

    public Packet next() {
        return nextLayer;
    }

    public String text() {
        return String.format("Ethernet: dhost:%s, shost:%s\n",
                Utils.bytes2MAC(data_buf, 0),
                Utils.bytes2MAC(data_buf, 6)
        );
    }

    public void print() {
        System.out.print(text());
    }

    public void printAll() {
        print();
        if(nextLayer != null)
            nextLayer.printAll();
        else
            System.out.println();
    }
}
