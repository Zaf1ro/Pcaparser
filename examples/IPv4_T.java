import com.jduan.pcaparser.*;

import java.util.Iterator;


public class IPv4_T {
    public static void main(String[] args) {
        TEST.timer.start();
        Pcap pcap = new Pcap(TEST.getDir() + "ipv4.pcap");
        pcap.unpack();
        TEST.timer.end("Unpack");

        TEST.timer.start();
        Iterator<Packet> iter = pcap.iterator();
        Packet eth = iter.next();
        if(eth instanceof Ethernet) {
            Packet ipv4 = eth.next();
            if(ipv4 instanceof IPv4) {
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
