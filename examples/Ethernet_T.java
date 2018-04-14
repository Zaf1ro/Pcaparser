import com.jduan.pcaparser.*;

import java.util.Iterator;


public class Ethernet_T {
    public static void main(String[] args) {
        TEST.timer.start();
        Pcap pcap = new Pcap(TEST.getDir() + "eth.pcap");
        pcap.unpack();
        TEST.timer.end("Unpack");

        TEST.timer.start();
        Iterator<Packet> iter = pcap.iterator();
        Packet eth = iter.next();
        if(eth instanceof Ethernet) {
            System.out.println("DHOST: " + eth.field(Ethernet.DHOST));
            System.out.println("SHOST: " + eth.field(Ethernet.SHOST));
            System.out.println("ETH_TYPE: " + eth.field(Ethernet.ETH_TYPE));
        }
        TEST.timer.end("PRINT");
    }
}
