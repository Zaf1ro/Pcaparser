import com.jduan.pcaparser.*;

import java.util.Iterator;

public class IPv6_T {
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
