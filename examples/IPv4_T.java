import com.jduan.pcaparser.*;

import java.util.Iterator;


public class IPv4_T {

    private static Packet ip;

    public static void main(String[] args) {
        TEST.timer.start();
        Pcap pcap = new Pcap(TEST.getDir() + "ipv4.pcap");
        pcap.unpack();
        TEST.timer.end("Unpack");

        TEST.timer.start();
        Iterator<Packet> iter = pcap.iterator();
        Packet eth = iter.next();
        if(eth instanceof Ethernet) {
            ip = eth.next();
            if(ip instanceof IPv4) {
                System.out.println("VERSION: " + ip.field(IPv4.VERSION));
                System.out.println("IHL: " + ip.field(IPv4.IHL));
                System.out.println("TOS: " + ip.field(IPv4.TOS));
                System.out.println("ECN: " + ip.field(IPv4.ECN));
                System.out.println("TOTAL LENGTH: " + ip.field(IPv4.TOTAL_LENGTH));
                System.out.println("IDENTIFICATION: " + ip.field(IPv4.IDENTIFICATION));
                System.out.println("FLAGS: " + ip.field(IPv4.FLAGS));
                System.out.println("FRAGMENT OFFSET: " + ip.field(IPv4.FRAGMENT_OFFSET));
                System.out.println("TTL: " + ip.field(IPv4.TTL));
                System.out.println("PROTOCOL: " + ip.field(IPv4.PROTOCOL));
                System.out.println("CHECKSUM: " + ip.field(IPv4.CHECKSUM));
                System.out.println("SRC IP: " + ip.field(IPv4.SRC_IP));
                System.out.println("DST IP: " + ip.field(IPv4.DST_IP));
                System.out.println("OPTIONS: " + ip.field(IPv4.OPTIONS));
            }
        }
        TEST.timer.end("PRINT");
    }
}
