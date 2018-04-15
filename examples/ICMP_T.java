import com.jduan.pcaparser.*;
import java.util.Iterator;


public class ICMP_T {
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
                    System.out.println("REST OF HEADER: " + icmp.field(ICMP.REST_OF_HEADER));
                }
            }
        }
        TEST.timer.end("PRINT");
    }
}
