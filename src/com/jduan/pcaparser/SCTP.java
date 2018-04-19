package com.jduan.pcaparser;

import java.util.Iterator;


/* https://en.wikipedia.org/wiki/SCTP_packet_structure#Common_header */
public class SCTP extends Protocol {
    public final static int SPORT = 0;      /* 2, the sending port */
    public final static int DPORT = 1;      /* 2, the receiving port */
    public final static int TAG = 2;        /* 4, A random value to distinguish stale packet */
    public final static int CHECKSUM = 3;   /* 4, error checking */

    private static final int SCTP_LEN = 12;
    private int start;

    SCTP(byte[] __buf, int __start) {
        assert (__buf != null);
        data_buf = __buf;
        start = __start;
        nextLayer = link();
    }

    private Protocol link() {
        return null;
    }

    public String field(int id) {
        assert (data_buf != null);
        switch (id) {
            case SPORT:
                return Short.toString(Utils.bBytes2Short(data_buf, start));
            case DPORT:
                return Short.toString(Utils.bBytes2Short(data_buf, start + 2));
            case TAG:
                return Utils.bytes2Hex(data_buf, start + 4, 4);
            case CHECKSUM:
                return Utils.bytes2Hex(data_buf, start + 8, 4);
            default:
                return null;
        }
    }

    public String type() {
        return "SCTP";
    }

    public String text() {
        return String.format("SCTP:\t SPORT:%s, DPORT:%s",
                field(SCTP.SPORT),
                field(SCTP.DPORT)
        );
    }

    public static void main(String[] args) {
        TEST.timer.start();
        Pcap pcap = new Pcap(TEST.getDir() + "sctp.pcap");
        pcap.unpack();
        TEST.timer.end("Unpack");

        TEST.timer.start();
        Iterator<Protocol> iter = pcap.iterator();
        Protocol eth = iter.next();
        if (eth instanceof Ethernet) {
            Protocol ipv4 = eth.next();
            if (ipv4 instanceof IPv4) {
                Protocol sctp = ipv4.next();
                if (sctp instanceof SCTP) {
                    System.out.println("SPORT: " + sctp.field(SCTP.SPORT));
                    System.out.println("DPORT: " + sctp.field(SCTP.DPORT));
                    System.out.println("VERIFICATION TAG: " + sctp.field(SCTP.TAG));
                    System.out.println("CHECKSUM: " + sctp.field(SCTP.CHECKSUM));
                }
            }
        }
        TEST.timer.end("PRINT");
    }
}
