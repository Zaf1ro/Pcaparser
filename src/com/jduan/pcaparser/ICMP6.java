package com.jduan.pcaparser;

import java.util.Iterator;

public class ICMP6 extends Protocol {
    public final static int TYPE = 0;            /* 1, ICMP type */
    public final static int CODE = 1;            /* 1, ICMP subtype */
    public final static int CHECKSUM = 2;        /* 2, Error checking data */

    private final static int ICMP6_LEN = 20;
    private int start;

    ICMP6(byte[] __buf, int __start) {
        assert(__buf != null);
        data_buf = __buf;
        start = __start;
    }

    public String field(int id) {
        assert(data_buf != null);
        switch (id) {
            case TYPE:
                return Integer.toString(data_buf[start] & 0xFF);
            case CODE:
                return Integer.toString(data_buf[start+1] & 0xFF);
            case CHECKSUM:
                return Utils.bytes2Hex(data_buf, start+2, 2);
            default:
                return null;
        }
    }

    public String type() {
        return "ICMP6";
    }

    public String text() {
        return String.format("ICMP6:\t TYPE:%s, CODE:%s",
                field(ICMP6.TYPE),
                field(ICMP6.CODE)
        );
    }

    public static void main(String[] args) {
        TEST.timer.start();
        Pcap pcap = new Pcap(TEST.getDir() + "icmp6.pcap");
        pcap.unpack();
        TEST.timer.end("Unpack");

        TEST.timer.start();
        Iterator<Protocol> iter = pcap.iterator();
        Protocol eth = iter.next();
        if(eth instanceof Ethernet) {
            Protocol ip4 = eth.next();
            if(ip4 instanceof IPv4) {
                Protocol ip6 = ip4.next();
                if(ip6 instanceof IPv6) {
                    Protocol icmp6 = ip6.next();
                    if(icmp6 instanceof ICMP6) {
                        System.out.println("TYPE: " + icmp6.field(ICMP.TYPE));
                        System.out.println("CODE: " + icmp6.field(ICMP.CODE));
                        System.out.println("CHECKSUM: " + icmp6.field(ICMP.CHECKSUM));
                    }
                }
            }
        }
        TEST.timer.end("PRINT");
    }
}
