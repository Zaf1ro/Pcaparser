import com.jduan.pcaparser.Ethernet;
import com.jduan.pcaparser.IPv4;
import com.jduan.pcaparser.Packet;
import com.jduan.pcaparser.Pcap;

import java.util.Iterator;


public class IPv4_T {
    public static void main(String[] args) {
        TEST.timer.start();
        Pcap pcap = new Pcap(TEST.getDir() + "ipv4.pcap");
        pcap.unpack();
        TEST.timer.end("Unpack");

        TEST.timer.start();
        Iterator<Packet> iter = pcap.iterator();
        while(iter.hasNext()) {
            Packet eth = iter.next();
            if(eth instanceof Ethernet) {
                Packet ip = eth.next();
                if(ip instanceof IPv4) {
                    ip.print();
                }
            }
        }
        TEST.timer.end("PRINT");
    }
}
