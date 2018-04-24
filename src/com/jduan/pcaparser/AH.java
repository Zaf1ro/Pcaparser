package com.jduan.pcaparser;
import java.util.Iterator;


/* http://www.networksorcery.com/enp/protocol/ah.htm */
public class AH extends Protocol {
    public final static int NEXT = 0;       /* 1, the next encapsulated protocol */
    public final static int LENGTH = 1;     /* 1, size of AH header */
    public final static int SPI = 2;        /* 4, a pseudo random value used to identify */
    public final static int SEQUENCE = 3;   /* 4, sequence number */
    public final static int ICV = 4;        /* variable, contains a multiple of 32bit words */

    private int ICV_LEN;
    private int start;

    AH(byte[] __buf, int __start) {
        assert(__buf != null);
        data_buf = __buf;
        start = __start;
        ICV_LEN = ((data_buf[start+1] & 0xFF) - 1)  * 4;
        nextLayer = link();
    }

    private Protocol link() {
        return null;
    }

    public String field(int id) {
        assert (data_buf != null);
        switch (id) {
            case NEXT:
                return Byte.toString(data_buf[start]);
            case LENGTH:
                return Byte.toString(data_buf[start+1]);
            case SPI:
                return Utils.bytes2Hex(data_buf, start+4, 4);
            case SEQUENCE:
                return Utils.bytes2Hex(data_buf, start+8, 4);
            case ICV:
                return Utils.bytes2Hex(data_buf, start+12, ICV_LEN);
            default:
                return null;
        }
    }

    public String type() {
        return "Authentication Header";
    }

    public String text() {
        return String.format("AH:\t SPI:%s, SEQUENCE:%s",
                field(AH.SPI),
                field(AH.SEQUENCE)
        );
    }

    public static void main(String[] args) {
        TEST.timer.start();
        Pcap pcap = new Pcap(TEST.getDir() + "ah.pcap");
        pcap.unpack();
        TEST.timer.end("Unpack");

        TEST.timer.start();
        Iterator<Protocol> iter = pcap.iterator();
        Protocol eth = iter.next();
        if (eth instanceof Ethernet) {
            Protocol ipv4 = eth.next();
            if (ipv4 instanceof IPv4) {
                Protocol ah = ipv4.next();
                if (ah instanceof AH) {
                    System.out.println("NEXT: " + ah.field(AH.NEXT));
                    System.out.println("LENGTH: " + ah.field(AH.LENGTH));
                    System.out.println("SPI: " + ah.field(AH.SPI));
                    System.out.println("SEQUENCE: " + ah.field(AH.SEQUENCE));
                    System.out.println("ICV: " + ah.field(AH.ICV));
                }
            }
        }
        TEST.timer.end("PRINT");
    }
}
