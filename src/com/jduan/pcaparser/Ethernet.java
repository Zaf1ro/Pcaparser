package com.jduan.pcaparser;


public final class Ethernet extends PktHdr {
    /* https://en.wikipedia.org/wiki/Ethernet_frame */
    public final static int DHOST = 0;      /* 6, Destination host address */
    public final static int SHOST = 6;      /* 6, Source host address */
    public final static int ETH_TYPE = 12;  /* 2, Type of ethernet */

    private final static int ETH_LEN = 14;

    private byte[] data_buf;
    private Packet nextLayer;

    Ethernet() {
        super();
        data_buf = new byte[super.data_len];
        Pcap.reader.fill(data_buf);
        link();
    }

    private void link() {
        /* get the layer 2 protocol */
        int type = Utils.byteArrayToShort(data_buf, 12);
        switch (type) {
            case 0x0800:        /* IPv4 protocol */
                nextLayer = new IPv4(data_buf, ETH_LEN);
                break;
//            case 0x86DD:        /* IPv6 protocol */
//                nextLayer = new IPv6(data_buf, 14);
//                break;
            case 0x0806:        /* address resolution protocol */
                nextLayer = new ARP(data_buf, ETH_LEN);
                break;
        }
    }

    public String field(int id) {
        switch (id) {
            case DHOST:
                return Utils.byteArrayToMAC(data_buf, 0);
            case SHOST:
                return Utils.byteArrayToMAC(data_buf, 6);
            case ETH_TYPE:
                return Short.toString(Utils.byteArrayToShort(data_buf, 12));
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
                Utils.byteArrayToMAC(data_buf, 0),
                Utils.byteArrayToMAC(data_buf, 6)
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
