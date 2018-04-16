package com.jduan.pcaparser;
import java.util.Iterator;


/* https://en.wikipedia.org/wiki/IPv6_packet */
public class IPv6 implements Packet {
    public final static int VERSION = 1;           /* 4b, version */
    public final static int TRAFFI_CLASS = 2;      /* 1, hold two values: DS, ECN */
    public final static int FLOW_LABEL = 3;        /* 20b,  label a set of packets belonging to a flow */
    public final static int PAYLOAD_LENGTH = 4;    /* 2, length of data */
    public final static int NEXT_HEADER = 5;       /* 1, type of the next header */
    public final static int HOP_LIMIT = 6;         /* 1, same as TTL */
    public final static int SRC_ADDR = 7;          /* 16, source address */
    public final static int DST_ADDR = 8;          /* 16, destination address */

    private int IPv6_LEN;
    private int payload_len;

    private byte[] data_buf;
    private int start;
    private Packet nextLayer;

    IPv6(byte[] __buf, int __start) {
        assert (__buf != null);
        data_buf = __buf;
        start = __start;
        payload_len = Utils.bytes2Short(data_buf, start+4);
        IPv6_LEN = data_buf.length - payload_len - start;
        nextLayer = link();
    }

    private Packet link() {
        int type = data_buf[start+6];   // next header
        switch (type) {
            case 0x03A:
                return new ICMP6(data_buf, data_buf.length-payload_len);
//            case 0x06:
//                return new TCP(data_buf, start + IPv6_LEN);
//            case 0x11:
//                nextLayer = new UDP(data_buf, start + IPv6_LEN);
            default:
                return null;
        }
    }

    public String field(int id) {
        assert(data_buf != null);
        switch (id) {
            case VERSION:
                return Integer.toString(data_buf[start] >>> 4);
            case TRAFFI_CLASS:
                return String.format("%x", (Utils.bytes2Short(data_buf, start) >>> 4) & 0xFF);
            case FLOW_LABEL:
                return String.format("%x", (data_buf[start+1] >>> 4) << 16 + Utils.bytes2Short(data_buf, start+2));
            case PAYLOAD_LENGTH:
                return Short.toString(Utils.bytes2Short(data_buf, start+4));
            case NEXT_HEADER:
                return Byte.toString(data_buf[start+6]);
            case HOP_LIMIT:
                return Byte.toString(data_buf[start+7]);
            case SRC_ADDR:
                return Utils.bytes2IPv6(data_buf, start+8);
            case DST_ADDR:
                return Utils.bytes2IPv6(data_buf, start+24);
            default:
                return null;
        }
    }

    public String type() {
        return "IPv6";
    }

    public Packet next() {
        return nextLayer;
    }

    public String text() {
        return String.format("IPv6: len:%d, src:%s, dst:%s\n",
                Utils.bytes2Short(data_buf, start+4),
                Utils.bytes2IPv6(data_buf, start+8),
                Utils.bytes2IPv6(data_buf, start+24)
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

    public static void main(String[] args) {
        TEST.timer.start();
        Pcap pcap = new Pcap(TEST.getDir() + "ipv6.pcap");
        pcap.unpack();
        TEST.timer.end("Unpack");

        TEST.timer.start();
        Iterator<Packet> iter = pcap.iterator();
        Packet eth = iter.next();
        if(eth instanceof Ethernet) {
            Packet ipv6 = eth.next();
            if(ipv6 instanceof IPv6) {
                System.out.println("VERSION: " + ipv6.field(IPv6.VERSION));
                System.out.println("TRAFFI CLASS: " + ipv6.field(IPv6.TRAFFI_CLASS));
                System.out.println("FLOW LABEL: " + ipv6.field(IPv6.FLOW_LABEL));
                System.out.println("PAYLOAD LENGTH: " + ipv6.field(IPv6.PAYLOAD_LENGTH));
                System.out.println("NEXT HEADER: " + ipv6.field(IPv6.NEXT_HEADER));
                System.out.println("HOP LIMIT: " + ipv6.field(IPv6.HOP_LIMIT));
                System.out.println("SRC ADDR: " + ipv6.field(IPv6.SRC_ADDR));
                System.out.println("DST ADDR: " + ipv6.field(IPv6.DST_ADDR));
            }
        }
        TEST.timer.end("PRINT");
    }
}
