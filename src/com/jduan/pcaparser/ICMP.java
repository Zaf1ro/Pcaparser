package com.jduan.pcaparser;
import java.util.Iterator;


/* https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Header */
public class ICMP implements Packet{
    public final static int TYPE = 0;            /* 1, ICMP type */
    public final static int CODE = 1;            /* 1, ICMP subtype */
    public final static int CHECKSUM = 2;        /* 2, Error checking data */

    private final static int ICMP_LEN = 20;

    private byte[] data_buf;
    private int start;
    private Packet nextLayer = null;    /* no next layer */

    ICMP(byte[] __buf, int __start) {
        assert (__buf != null);
        data_buf = __buf;
        start = __start;
    }

    public String field(int id) {
        assert(data_buf != null);
        switch (id) {
            case TYPE:
                return Byte.toString(data_buf[start]);
            case CODE:
                return Byte.toString(data_buf[start+1]);
            case CHECKSUM:
                return Utils.bytes2Hex(data_buf, start+2, 2);
            default:
                return null;
        }
    }

    public String type() {
        return "ICMP";
    }

    public Packet next() {
        return nextLayer;
    }

    public String text() {
        return String.format("ICMP: len:%d, id:0x%04x, src:%s, dst:%s\n",
                Utils.bytes2Short(data_buf, start+2),
                Utils.bytes2Short(data_buf, start+4),
                Utils.bytes2IPv4(data_buf, start+12),
                Utils.bytes2IPv4(data_buf, start+16)
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
        Pcap pcap = new Pcap(TEST.getDir() + "icmp.pcap");
        pcap.unpack();
        TEST.timer.end("Unpack");

        TEST.timer.start();
        Iterator<Packet> iter = pcap.iterator();
        Packet eth = iter.next();
        if(eth instanceof Ethernet) {
            Packet ip = eth.next();
            if(ip instanceof IPv4) {
                Packet icmp = ip.next();
                if(icmp instanceof ICMP) {
                    System.out.println("TYPE: " + icmp.field(ICMP.TYPE));
                    System.out.println("CODE: " + icmp.field(ICMP.CODE));
                    System.out.println("CHECKSUM: " + icmp.field(ICMP.CHECKSUM));
                }
            }
        }
        TEST.timer.end("PRINT");
    }
}
