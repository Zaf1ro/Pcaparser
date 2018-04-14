import com.jduan.pcaparser.Ethernet;
import com.jduan.pcaparser.PPP;
import com.jduan.pcaparser.Packet;
import com.jduan.pcaparser.Pcap;

import java.util.Iterator;

public class PPP_T {
    public static void main(String[] args) {
        TEST.timer.start();
        Pcap pcap = new Pcap(TEST.getDir() + "ppp.pcap");
        pcap.unpack();
        TEST.timer.end("Unpack");

        TEST.timer.start();
        Iterator<Packet> iter = pcap.iterator();
        Packet ppp = iter.next();
        if(ppp instanceof PPP) {
            System.out.println("ADDR: " + ppp.field(PPP.ADDR));
            System.out.println("CONTROL: " + ppp.field(PPP.CONTROL));
            System.out.println("PROTOCOL: " + ppp.field(PPP.CONTROL));
        }
        TEST.timer.end("PRINT");
    }
}
