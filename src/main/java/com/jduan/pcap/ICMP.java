package com.jduan.pcap;

import java.util.Iterator;


/* https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Header */
public class ICMP extends Protocol {
    public final static int TYPE = 0;            /* 1, ICMP type */
    public final static int CODE = 1;            /* 1, ICMP subtype */
    public final static int CHECKSUM = 2;        /* 2, Error checking data */

    private final static int ICMP_LEN = 20;
    private int start;

    ICMP(byte[] __buf, int __start) {
        assert (__buf != null);
        data_buf = __buf;
        start = __start;
    }

    public String field(int id) {
        assert (data_buf != null);
        switch (id) {
            case TYPE:
                return Byte.toString(data_buf[start]);
            case CODE:
                return Byte.toString(data_buf[start + 1]);
            case CHECKSUM:
                return Utils.bytes2Hex(data_buf, start + 2, 2);
            default:
                return null;
        }
    }

    public String type() {
        return "ICMP";
    }

    public String text() {
        return String.format("ICMP:\t TYPE:%s, CODE:%s",
                field(ICMP.TYPE),
                field(ICMP.CODE)
        );
    }

    public static void main(String[] args) {
        Pcap pcap = new Pcap("icmp.pcap");
        pcap.unpack();
        Iterator<Protocol> iter = pcap.iterator();
        Protocol eth = iter.next();
        if (eth instanceof Ethernet) {
            Protocol ip = eth.next();
            if (ip instanceof IPv4) {
                Protocol icmp = ip.next();
                if (icmp instanceof ICMP) {
                    System.out.println("TYPE: " + icmp.field(ICMP.TYPE));
                    System.out.println("CODE: " + icmp.field(ICMP.CODE));
                    System.out.println("CHECKSUM: " + icmp.field(ICMP.CHECKSUM));
                }
            }
        }
    }
}
