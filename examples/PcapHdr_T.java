import com.jduan.pcaparser.*;

import java.util.Iterator;


public class PcapHdr_T {
    public static void main(String[] args) {
        TEST.timer.start();
        Pcap pcap = new Pcap(TEST.getDir() + "ipv4.pcap");
        pcap.unpack();
        TEST.timer.end("Unpack");

        TEST.timer.start();

        Packet pcap_hdr = pcap.pcapHdr;
        System.out.println("MAGIC: " + pcap_hdr.field(PcapHdr.MAGIC));
        System.out.println("V_MAJOR: " + pcap_hdr.field(PcapHdr.V_MAJOR));
        System.out.println("V_MINOR: " + pcap_hdr.field(PcapHdr.V_MINOR));
        System.out.println("THISZONE: " + pcap_hdr.field(PcapHdr.THISZONE));
        System.out.println("SIGFIGS: " + pcap_hdr.field(PcapHdr.SIGFIGS));
        System.out.println("SNAPLEN: " + pcap_hdr.field(PcapHdr.SNAPLEN));
        System.out.println("LINKTYPE: " + pcap_hdr.field(PcapHdr.LINKTYPE));

        TEST.timer.end("PRINT");
    }
}
