package com.jduan.pcaparser;


public class ARP implements Packet {
    public final static int HTYPE = 1;     /* 2, Type of network protocol type */
    public final static int PTYPE = 2;     /* 2, Type of internetwork protocol */
    public final static int HLEN = 3;      /* 1, Hardware address length */
    public final static int PLEN = 4;      /* 1, Protocol address length */
    public final static int OPERATION = 5; /* 2, Operation */
    public final static int SHA = 6;       /* 6, Sender hardware address  */
    public final static int SPA = 7;       /* 4, Sender protocol address */
    public final static int THA = 8;       /* 6, Target hardware address */
    public final static int TPA = 9;       /* 4, Target protocol address */

    private final static int ARP_LEN = 26;

    private byte[] data_buf;
    private int start;
    private Packet nextLayer;

    ARP(byte[] __buf, int __start) {
        assert (__buf != null);
        data_buf = __buf;
        start = __start;
    }

    public String field(int id) {
        switch (id) {
            case HTYPE:
                return Short.toString(Utils.bytes2Short(data_buf, start));
            case PTYPE:
                return Short.toString(Utils.bytes2Short(data_buf, start+2));
            case HLEN:
                return Byte.toString(data_buf[start+4]);
            case PLEN:
                return Byte.toString(data_buf[start+5]);
            case OPERATION:
                return Short.toString(Utils.bytes2Short(data_buf, start+6));
            case SHA:
                return Utils.bytes2MAC(data_buf, start+8);
            case SPA:
                return Utils.bytes2IPv4(data_buf, start+14);
            case THA:
                return Utils.bytes2MAC(data_buf, start+18);
            case TPA:
                return Utils.bytes2IPv4(data_buf, start+24);
            default:
                return null;
        }
    }

    public String type() {
        return "ARP";
    }

    public Packet next() {
        return nextLayer;
    }

    public String text() {
        return String.format("ARP: sha:%s, spa:%s,\t tha:%s tpa:%s\n",
                Utils.bytes2MAC(data_buf, start+8),
                Utils.bytes2IPv4(data_buf, start+14),
                Utils.bytes2MAC(data_buf, start+18),
                Utils.bytes2IPv4(data_buf,  start+24)
        );
    }

    public void print() {
        System.out.print(text());
    }

    public void printAll() {
        print();
        if(nextLayer != null)
            nextLayer.print();
        else
            System.out.println();
    }
}
