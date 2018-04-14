import com.jduan.pcaparser.*;
import java.util.Iterator;


public class IEEE80211_T {
    public static void main(String[] args) {
        TEST.timer.start();
        Pcap pcap = new Pcap(TEST.getDir() + "ieee802_11.pcap");
        pcap.unpack();
        TEST.timer.end("Unpack");

        TEST.timer.start();
        Iterator<Packet> iter = pcap.iterator();
        Packet ieee802_11 = iter.next();
        if(ieee802_11 instanceof IEEE80211) {
            System.out.println("FRAME_CONTROL: " + ieee802_11.field(IEEE80211.FRAME_CONTROL));
            System.out.println("DURATION: " + ieee802_11.field(IEEE80211.DURATION));
            System.out.println("ADDR1: " + ieee802_11.field(IEEE80211.ADDR1));
            System.out.println("ADDR2: " + ieee802_11.field(IEEE80211.ADDR2));
            System.out.println("ADDR3: " + ieee802_11.field(IEEE80211.ADDR3));
            System.out.println("SEQUENCE: " + ieee802_11.field(IEEE80211.SEQUENCE));
        }
        TEST.timer.end("PRINT");
    }
}
