package com.jduan.pcaparser;


// TODO: decode OSPF message
/* http://www.tcpipguide.com/free/t_OSPFMessageFormats.htm */
public class OSPF implements Packet {
    public final static int VERSION = 0;        /* 1, Version Number */
    public final static int TYPE = 1;           /* 1, type of OSPF message */
    public final static int PACKET_LENGTH = 2;  /* 2, Packet Length */
    public final static int ROUTER_ID = 3;      /* 4, The ID of the router */
    public final static int AREA_ID = 4;        /* 4, An identification of the OSPF area */
    public final static int CHECKSUM = 5;       /* 2, standard IP checksum */
    public final static int AUTYPE = 6;         /* 2, authentication type */
    public final static int AUTHENTICATION = 7; /* 8, authentication of the message */

    private final static int OSPF_LEN = 24;

    private byte[] data_buf;
    private int start;
    private Packet nextLayer;

    OSPF(byte[] __buf, int __start) {
        assert (__buf != null);
        data_buf = __buf;
        start = __start;
        nextLayer = link();
    }

    private Packet link() {
        return null;
    }

    public String field(int id) {
        assert(data_buf != null);

        switch (id) {
            case VERSION:
                return Byte.toString(data_buf[start]);
            case TYPE:
                return Byte.toString(data_buf[start+1]);
            case PACKET_LENGTH:
                return Short.toString(Utils.bytes2Short(data_buf, start+2));
            case ROUTER_ID:
                return Utils.bytes2IPv4(data_buf, start+4);
            case AREA_ID:
                return Utils.bytes2IPv4(data_buf, start+8);
            case CHECKSUM:
                return String.format("%02x", Utils.bytes2Short(data_buf, start+12));
            case AUTYPE:
                return Short.toString(Utils.bytes2Short(data_buf, start+14));
            case AUTHENTICATION:
                return Utils.bytes2Hex(data_buf, start+16, 8);
            default:
                return null;
        }
    }

    public String type() {
        return "OSPF";
    }

    public Packet next() {
        return nextLayer;
    }

    public String text() {
        return String.format("OSPF: router id:%04x, area id:%04x\n",
                Utils.bytes2Int(data_buf, start+4),
                Utils.bytes2Int(data_buf, start+8)
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
