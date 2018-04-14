import com.jduan.pcaparser.*;
import java.util.Iterator;


public class ARP_T {
    public static void main(String[] args) {
        TEST.timer.start();
        Pcap pcap = new Pcap(TEST.getDir() + "arp.pcap");
        pcap.unpack();
        TEST.timer.end("Unpack");

        TEST.timer.start();
        Iterator<Packet> iter = pcap.iterator();
        Packet eth = iter.next();
        if(eth instanceof Ethernet) {
            Packet arp = eth.next();
            if(arp instanceof ARP) {
                System.out.println("HTYPE: " + arp.field(ARP.HTYPE));
                System.out.println("PTYPE: " + arp.field(ARP.PTYPE));
                System.out.println("HLEN: " + arp.field(ARP.HLEN));
                System.out.println("PLEN: " + arp.field(ARP.PLEN));
                System.out.println("OPERATION: " + arp.field(ARP.OPERATION));
                System.out.println("SHA: " + arp.field(ARP.SHA));
                System.out.println("SPA: " + arp.field(ARP.SPA));
                System.out.println("THA: " + arp.field(ARP.THA));
                System.out.println("TPA: " + arp.field(ARP.TPA));
            }
        }
        TEST.timer.end("PRINT");
    }
}
