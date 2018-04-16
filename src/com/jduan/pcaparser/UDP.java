package com.jduan.pcaparser;
import java.util.Iterator;


/* https://en.wikipedia.org/wiki/User_Datagram_Protocol#Packet_structure */
public class UDP extends Protocol {
    public final static int SPORT = 0;      /* 2, the sending port */
    public final static int DPORT = 1;      /* 2, the receiving port */
    public final static int LENGTH = 2;        /* 4, Sequence number */
    public final static int CHECKSUM = 3;        /* 4, Acknowledgment number */

    private static final int UDP_LEN = 8;
    private int start;

    UDP(byte[] __buf, int __start) {
        assert (__buf != null);
        data_buf = __buf;
        start = __start;
        nextLayer = link();
    }

    private Protocol link() {
        return null;
    }

    public String field(int id) {
        assert(data_buf != null);

        switch (id) {
            case SPORT:
                return Short.toString(Utils.bytes2Short(data_buf, start));
            case DPORT:
                return Short.toString(Utils.bytes2Short(data_buf, start+2));
            case LENGTH:
                return Short.toString(Utils.bytes2Short(data_buf, start+4));
            case CHECKSUM:
                return Utils.bytes2Hex(data_buf, start+6, 2);
            default:
                return null;
        }
    }

    public String type() {
        return "UDP";
    }

    public String text() {
        return String.format("UDP:\t SPORT:%s, DPORT:%s",
                field(UDP.SPORT),
                field(UDP.DPORT)
        );
    }

    public static void main(String[] args) {
        TEST.timer.start();
        Pcap pcap = new Pcap(TEST.getDir() + "udp.pcap");
        pcap.unpack();
        TEST.timer.end("Unpack");

        TEST.timer.start();
        Iterator<Protocol> iter = pcap.iterator();
        Protocol eth = iter.next();
        if(eth instanceof Ethernet) {
            Protocol ipv4 = eth.next();
            if(ipv4 instanceof IPv4) {
                Protocol udp = ipv4.next();
                if(udp instanceof UDP) {
                    System.out.println("SPORT: " + udp.field(UDP.SPORT));
                    System.out.println("DPORT: " + udp.field(UDP.DPORT));
                    System.out.println("LENGTH: " + udp.field(UDP.LENGTH));
                    System.out.println("ACK: " + udp.field(UDP.CHECKSUM));
                }
            }
        }
        TEST.timer.end("PRINT");
    }
}
