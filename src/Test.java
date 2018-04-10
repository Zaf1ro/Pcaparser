import com.jduan.pcaparser.Packet;
import com.jduan.pcaparser.Pcap;

import java.util.Iterator;

public class Test {
    public static void main(String[] args) {
        byte[] s = {};

        long start = System.currentTimeMillis();
        Pcap pcap = new Pcap("C:\\Users\\zafiro\\Desktop\\pcaparser\\sample\\" + "test.pcap");
        pcap.unpack();
        Iterator<Packet> iter = pcap.iterator();
        while(iter.hasNext()) {
            Packet p = iter.next();
        }
        long end = System.currentTimeMillis();
        System.out.printf("%s: %d\n", "Spend time", end - start);
    }
}
