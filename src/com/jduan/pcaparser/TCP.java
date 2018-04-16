package com.jduan.pcaparser;
import java.util.Arrays;
import java.util.Iterator;


/* Transmission_Control_Protocol#TCP_segment_structure */
public class TCP implements Packet {
    public final static int SPORT = 0;      /* 2, the sending port */
    public final static int DPORT = 1;      /* 2, the receiving port */
    public final static int SEQ = 2;        /* 4, Sequence number */
    public final static int ACK = 3;        /* 4, Acknowledgment number */
    public final static int OFFSET = 4;     /* 4b, the size of the TCP header */
    public final static int FLAGS = 5;      /* 9b, Control bits */
    public final static int WINDOW = 6;     /* 2, The size of the receive window */
    public final static int CHECKSUM = 7;   /* 2, error-checking of the header */
    public final static int URP = 8;        /* 2, determined by the data offset field */

    private byte[] data_buf;
    private int start;
    private int TCP_LEN;
    private Packet nextLayer;

    TCP(byte[] __buf, int __start) {
        assert (__buf != null);
        data_buf = __buf;
        start = __start;
        nextLayer = link();
    }

    private Packet link() {
//        int type = data_buf[start+9];     // proto
//        switch (type) {
//            default:
//                return null;
//        }
        return null;
    }

    public String field(int id) {
        assert(data_buf != null);

        switch (id) {
            case SPORT:
                return Short.toString(Utils.bytes2Short(data_buf, start));
            case DPORT:
                return Short.toString(Utils.bytes2Short(data_buf, start+2));
            case SEQ:
                return Utils.bytes2Hex(data_buf, start+4, 4);
            case ACK:
                return Utils.bytes2Hex(data_buf, start+8, 4);
            case OFFSET:
                return Integer.toString((data_buf[start+12] >>> 4) & 0x0F);
            case FLAGS:
                return String.format("%04x", Utils.bytes2Short(data_buf, start+12) & 0x01FF);
            case WINDOW:
                return Integer.toString(Utils.bytes2Short(data_buf, start+14) & 0xFFFF);
            case CHECKSUM:
                return Utils.bytes2Hex(data_buf, start+16, 2);
            case URP:
                return Short.toString(Utils.bytes2Short(data_buf, start+18));
            default:
                return null;
        }
    }

    public String type() {
        return "TCP";
    }

    public Packet next() {
        return nextLayer;
    }

    public String text() {
        return String.format("TCP: sport:%d, dport:%d\n",
                Utils.bytes2Short(data_buf, start),
                Utils.bytes2Short(data_buf, start+2)
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
        Pcap pcap = new Pcap(TEST.getDir() + "tcp.pcap");
        pcap.unpack();
        TEST.timer.end("Unpack");

        TEST.timer.start();
        Iterator<Packet> iter = pcap.iterator();
        Packet eth = iter.next();
        if(eth instanceof Ethernet) {
            Packet ipv4 = eth.next();
            if(ipv4 instanceof IPv4) {
                Packet tcp = ipv4.next();
                if(tcp instanceof TCP) {
                    System.out.println("SPORT: " + tcp.field(TCP.SPORT));
                    System.out.println("DPORT: " + tcp.field(TCP.DPORT));
                    System.out.println("SEQ: " + tcp.field(TCP.SEQ));
                    System.out.println("ACK: " + tcp.field(TCP.ACK));
                    System.out.println("OFFSET : " + tcp.field(TCP.OFFSET));
                    System.out.println("FLAGS " + tcp.field(TCP.FLAGS));
                    System.out.println("WINDOW: " + tcp.field(TCP.WINDOW));
                    System.out.println("CHECKSUM: " + tcp.field(TCP.CHECKSUM));
                    System.out.println("URP: " + tcp.field(TCP.URP));
                }

            }
        }
        TEST.timer.end("PRINT");
    }
}