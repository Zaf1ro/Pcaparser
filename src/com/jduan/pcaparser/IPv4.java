package com.jduan.pcaparser;

import java.util.Arrays;
import java.util.Iterator;


/* https://en.wikipedia.org/wiki/IPv4#Header */
public final class IPv4 extends Protocol {
    public final static int VERSION = 0;            /* 4b, version */
    public final static int IHL = 1;                /* 4b, internet Header Length */
    public final static int TOS = 2;                /* 6b, type of service */
    public final static int ECN = 3;                /* 2b, explicit Congestion Notification */
    public final static int TOTAL_LENGTH = 4;       /* 2, entire size including header and data */
    public final static int IDENTIFICATION = 5;     /* 2, identify the group of fragment */
    public final static int FLAGS = 6;              /* 3b, control fragment */
    public final static int FRAGMENT_OFFSET = 7;    /* 13b, offset of a particular fragment */
    public final static int TTL = 8;                /* 1, datagram's lifetime */
    public final static int PROTOCOL = 9;           /* 1, protocol number */
    public final static int CHECKSUM = 10;          /* 2, error-checking */
    public final static int SRC_ADDR = 11;          /* 4, ICMP address of sender */
    public final static int DST_ADDR = 12;          /* 4, ICMP address of the receiver */
    public final static int OPTIONS = 13;           /* 20, options field */

    private final static int IPv4_LEN = 20;
    private int start;

    IPv4(byte[] __buf, int __start) {
        assert (__buf != null);
        data_buf = __buf;
        start = __start;
        nextLayer = link();
    }

    private Protocol link() {
        int type = data_buf[start + 9] & 0xFF;     // protocol
        switch (type) {
            case 0x01:
                return new ICMP(data_buf, start + IPv4_LEN);
            case 0x06:
                return new TCP(data_buf, start + IPv4_LEN);
            case 0x11:
                return new UDP(data_buf, start + IPv4_LEN);
            case 0x29:
                return new IPv6(data_buf, start + IPv4_LEN);
            case 0x32:
                return new ESP(data_buf, start + IPv4_LEN);
            case 0x84:
                return new SCTP(data_buf, start + IPv4_LEN);
            case 0x59:
                return new OSPF(data_buf, start + IPv4_LEN);
            default:
                return null;
        }
    }

    public String field(int id) {
        assert (data_buf != null);
        switch (id) {
            case VERSION:
                return Integer.toString((data_buf[start] >>> 4) & 0xFF);
            case IHL:
                return Integer.toString(data_buf[start] & 0x0F);
            case TOS:
                return String.format("0x%02x", (data_buf[start + 1] >>> 2) & 0x3F);
            case ECN:
                return Integer.toString(data_buf[start + 1] & 0x03);
            case TOTAL_LENGTH:
                return Short.toString(Utils.bytes2Short(data_buf, start + 2));
            case IDENTIFICATION:
                return String.format("0x%04x", Utils.bytes2Short(data_buf, start + 4));
            case FLAGS:
                return String.format("0x%02x", (data_buf[start + 6] >>> 5) & 0x7);
            case FRAGMENT_OFFSET:
                return Integer.toString(Utils.bytes2Short(data_buf, start + 6) & 0x1FFF);
            case TTL:
                return Byte.toString(data_buf[start + 8]);
            case PROTOCOL:
                return Byte.toString(data_buf[start + 9]);
            case CHECKSUM:
                return String.format("0x%04x", Utils.bytes2Short(data_buf, start + 10));
            case SRC_ADDR:
                return Utils.bytes2IPv4(data_buf, start + 12);
            case DST_ADDR:
                return Utils.bytes2IPv4(data_buf, start + 16);
            case OPTIONS:
                return (data_buf[start] & 0x0F) > 5 ?
                        new String(Arrays.copyOfRange(data_buf, start + 20, start + 36)) : "";
            default:
                return null;
        }
    }

    public String type() {
        return "IPv4";
    }

    public String text() {
        return String.format("IPv4:\t SRC IP:%s, DST IP:%s",
                field(IPv4.SRC_ADDR),
                field(IPv4.DST_ADDR)
        );
    }

    public static void main(String[] args) {
        TEST.timer.start();
        Pcap pcap = new Pcap(TEST.getDir() + "ipv4.pcap");
        pcap.unpack();
        TEST.timer.end("Unpack");

        TEST.timer.start();
        Iterator<Protocol> iter = pcap.iterator();
        Protocol eth = iter.next();
        if (eth instanceof Ethernet) {
            Protocol ipv4 = eth.next();
            if (ipv4 instanceof IPv4) {
                System.out.println("VERSION: " + ipv4.field(IPv4.VERSION));
                System.out.println("IHL: " + ipv4.field(IPv4.IHL));
                System.out.println("TOS: " + ipv4.field(IPv4.TOS));
                System.out.println("ECN: " + ipv4.field(IPv4.ECN));
                System.out.println("TOTAL LENGTH: " + ipv4.field(IPv4.TOTAL_LENGTH));
                System.out.println("IDENTIFICATION: " + ipv4.field(IPv4.IDENTIFICATION));
                System.out.println("FLAGS: " + ipv4.field(IPv4.FLAGS));
                System.out.println("FRAGMENT OFFSET: " + ipv4.field(IPv4.FRAGMENT_OFFSET));
                System.out.println("TTL: " + ipv4.field(IPv4.TTL));
                System.out.println("PROTOCOL: " + ipv4.field(IPv4.PROTOCOL));
                System.out.println("CHECKSUM: " + ipv4.field(IPv4.CHECKSUM));
                System.out.println("SRC ADDR: " + ipv4.field(IPv4.SRC_ADDR));
                System.out.println("DST ADDR: " + ipv4.field(IPv4.DST_ADDR));
                System.out.println("OPTIONS: " + ipv4.field(IPv4.OPTIONS));
            }
        }
        TEST.timer.end("PRINT");
    }
}
