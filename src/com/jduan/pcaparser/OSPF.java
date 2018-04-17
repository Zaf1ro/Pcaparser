package com.jduan.pcaparser;

import java.util.Iterator;


// TODO: decode OSPF message
/* http://www.tcpipguide.com/free/t_OSPFMessageFormats.htm */
public class OSPF extends Protocol {
    public final static int VERSION = 0;        /* 1, Version Number */
    public final static int TYPE = 1;           /* 1, type of OSPF message */
    public final static int PACKET_LENGTH = 2;  /* 2, Protocol Length */
    public final static int ROUTER_ID = 3;      /* 4, The ID of the router */
    public final static int AREA_ID = 4;        /* 4, An identification of the OSPF area */
    public final static int CHECKSUM = 5;       /* 2, standard IP checksum */
    public final static int AUTYPE = 6;         /* 2, authentication type */
    public final static int AUTHENTICATION = 7; /* 8, authentication of the message */

    private final static int OSPF_LEN = 24;
    private int start;

    OSPF(byte[] __buf, int __start) {
        assert (__buf != null);
        data_buf = __buf;
        start = __start;
    }

    public String field(int id) {
        assert (data_buf != null);
        switch (id) {
            case VERSION:
                return Byte.toString(data_buf[start]);
            case TYPE:
                return Byte.toString(data_buf[start + 1]);
            case PACKET_LENGTH:
                return Short.toString(Utils.bytes2Short(data_buf, start + 2));
            case ROUTER_ID:
                return Utils.bytes2IPv4(data_buf, start + 4);
            case AREA_ID:
                return Utils.bytes2IPv4(data_buf, start + 8);
            case CHECKSUM:
                return String.format("0x%02x", Utils.bytes2Short(data_buf, start + 12));
            case AUTYPE:
                return Short.toString(Utils.bytes2Short(data_buf, start + 14));
            case AUTHENTICATION:
                return Utils.bytes2Hex(data_buf, start + 16, 8);
            default:
                return null;
        }
    }

    public String type() {
        return "OSPF";
    }

    public String text() {
        return String.format("OSPF:\t ROUTER ID:%s, AREA ID:%s",
                field(OSPF.ROUTER_ID),
                field(OSPF.AREA_ID)
        );
    }

    public static void main(String[] args) {
        TEST.timer.start();
        Pcap pcap = new Pcap(TEST.getDir() + "ospf.pcap");
        pcap.unpack();
        TEST.timer.end("Unpack");

        TEST.timer.start();
        Iterator<Protocol> iter = pcap.iterator();
        Protocol eth = iter.next();
        if (eth instanceof Ethernet) {
            Protocol ip = eth.next();
            if (ip instanceof IPv4) {
                Protocol ospf = ip.next();
                if (ospf instanceof OSPF) {
                    System.out.println("VERSION: " + ospf.field(OSPF.VERSION));
                    System.out.println("TYPE: " + ospf.field(OSPF.TYPE));
                    System.out.println("PACKET_LENGTH: " + ospf.field(OSPF.PACKET_LENGTH));
                    System.out.println("ROUTER_ID: " + ospf.field(OSPF.ROUTER_ID));
                    System.out.println("AREA_ID: " + ospf.field(OSPF.AREA_ID));
                    System.out.println("CHECKSUM: " + ospf.field(OSPF.CHECKSUM));
                    System.out.println("AUTYPE: " + ospf.field(OSPF.AUTYPE));
                    System.out.println("AUTHENTICATION: " + ospf.field(OSPF.AUTHENTICATION));
                }
            }
        }
        TEST.timer.end("PRINT");
    }
}
