import com.jduan.pcaparser.*;
import java.util.Iterator;


public class OSPF_T {
    public static void main(String[] args) {
        TEST.timer.start();
        Pcap pcap = new Pcap(TEST.getDir() + "ospf.pcap");
        pcap.unpack();
        TEST.timer.end("Unpack");

        TEST.timer.start();
        Iterator<Packet> iter = pcap.iterator();
        Packet eth = iter.next();
        if(eth instanceof Ethernet) {
            Packet ip = eth.next();
            if(ip instanceof IPv4) {
                Packet ospf = ip.next();
                if(ospf instanceof OSPF) {
                    System.out.println("VERSION: " + ospf.field(OSPF.VERSION));
                    System.out.println("TYPE: " + ospf.field(OSPF.TYPE));
                    System.out.println("PACKET_LENGTH: " + ospf.field(OSPF.PACKET_LENGTH));
                    System.out.println("ROUTER_ID: " + ospf.field(OSPF.ROUTER_ID));
                    System.out.println("AREA_ID: " + ospf.field(OSPF.AREA_ID));
                    System.out.println("CHECKSUM: " + ospf.field(OSPF.CHECKSUM));
                    System.out.println("AUTYPE: " + ospf.field(OSPF.AUTYPE));
                    System.out.println("AUTHENTICATION: " + ospf.field(OSPF.AUTHENTICATION));
                }
            }
        }
        TEST.timer.end("PRINT");
    }
}
