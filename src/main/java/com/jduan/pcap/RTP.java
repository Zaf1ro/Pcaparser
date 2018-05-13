package com.jduan.pcap;
import java.util.Iterator;


/* http://www.networksorcery.com/enp/protocol/rtp.htm */
public class RTP extends Protocol {
    public final static int VERSION = 0;    /* 2b, version number */
    public final static int P = 1;          /* 1b, if set, it contains additional padding */
    public final static int X = 2;          /* 1b, if set, it contains one more header extension */
    public final static int CC = 3;         /* 4b, the number of CSRC identifiers */
    public final static int M = 4;          /* 1b, the interpretation of the marker */
    public final static int PT = 5;         /* 7b, the format of RTP payload */
    public final static int SEQUENCE = 6;    /* the squence number incremented by one for each RTP data */
    public final static int TIMESTAMP = 7;  /* 4, derived from a clock that increments monotonically */
    public final static int SSRC = 8;       /* 4, random number to identify the synchronization source */

    private int start;
    private int RTP_LEN = 12;

    RTP(byte[] __buf, int __start) {
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
            case VERSION:
                return Integer.toString((data_buf[start] >>> 6) & 0x03);
            case P:
                return Integer.toString((data_buf[start] >>> 5) & 0x01);
            case X:
                return Integer.toString((data_buf[start] >>> 4) & 0x01);
            case CC:
                return Integer.toString(data_buf[start] & 0x0F);
            case M:
                return Integer.toString((data_buf[start+1] >>> 7) & 0x01);
            case PT:
                return Integer.toString(data_buf[start+1] & 0x7F);
            case SEQUENCE:
                return Short.toString(Utils.bBytes2Short(data_buf, start+2));
            case TIMESTAMP:
                return Integer.toString(Utils.bBytes2Int(data_buf, start+4));
            case SSRC:
                return Integer.toString(Utils.bBytes2Int(data_buf, start+8));
            default:
                return null;
        }
    }

    public String type() {
        return "RTP";
    }

    public String text() {
        return String.format("RTP:\t VERSION:%s",
                field(RTP.VERSION)
        );
    }

    public static void main(String[] args) {
        Pcap pcap = new Pcap("rtp.pcap");
        pcap.unpack();

        Iterator<Protocol> iter = pcap.iterator();
        Protocol eth = iter.next();
        if (eth instanceof Ethernet) {
            Protocol ipv4 = eth.next();
            if (ipv4 instanceof IPv4) {
                Protocol udp = ipv4.next();
                if (udp instanceof UDP) {
                    Protocol dns = udp.next();
                    if(dns instanceof DNS) {
                        System.out.println("ID: " + dns.field(DNS.ID));
                        System.out.println("QR: " + dns.field(DNS.QR));
                        System.out.println("OPCODE: " + dns.field(DNS.OPCODE));
                        System.out.println("AA: " + dns.field(DNS.AA));
                        System.out.println("TC: " + dns.field(DNS.TC));
                        System.out.println("RD: " + dns.field(DNS.RD));
                        System.out.println("RA: " + dns.field(DNS.RA));
                        System.out.println("RCODE: " + dns.field(DNS.RCODE));
                        System.out.println("QDCOUNT: " + dns.field(DNS.QDCOUNT));
                        System.out.println("ANCOUNT: " + dns.field(DNS.ANCOUNT));
                        System.out.println("NSCOUNT: " + dns.field(DNS.NSCOUNT));
                        System.out.println("ARCOUNT: " + dns.field(DNS.ARCOUNT));
                    }
                }
            }
        }
    }
}
