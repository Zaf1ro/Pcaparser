import com.jduan.pcaparser.Packet;
import com.jduan.pcaparser.Pcap;

import java.io.File;
import java.io.IOException;
import java.util.Iterator;


public class IPv4_Test {
    public static void main(String[] args) {
        String pcap_path = "";
        try {
            File dir = new File("examples");
            pcap_path = dir.getCanonicalPath() + File.separator +
                    "data" + File.separator + "ipv4.pcap";
        } catch (IOException e) {
            e.printStackTrace();
        }

        long start = System.currentTimeMillis();

        Pcap pcap = new Pcap(pcap_path);
        pcap.unpack();
        Iterator<Packet> iter = pcap.iterator();
        while(iter.hasNext()) {
            Packet p = iter.next();
            p.print();
        }

        long end = System.currentTimeMillis();
        System.out.printf("%s: %d\n", "Spend time", end - start);
    }
}
