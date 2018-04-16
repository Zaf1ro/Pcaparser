package com.jduan.pcaparser;
import java.util.Iterator;


/* https://en.wikipedia.org/wiki/IPsec#Encapsulating_Security_Payload */
public class ESP implements Packet {
    public final static int SPI = 0;        /* 4, Security Parameters Index */
    public final static int SEQUENCE = 1;   /* 4, A sequence number to protect against replay attacks */

    private final static int ESP_LEN = 8;

    private byte[] data_buf;
    private int start;
    private Packet nextLayer = null;    /* no next layer */

    ESP(byte[] __buf, int __start) {
        assert (__buf != null);
        data_buf = __buf;
        start = __start;
    }

    public String field(int id) {
        assert(data_buf != null);

        switch (id) {
            case SPI:
                return Utils.bytes2Hex(data_buf, start, 4);
            case SEQUENCE:
                return Integer.toString(Utils.bytes2Int(data_buf, start+4));
            default:
                return null;
        }
    }

    public String type() {
        return "ESP";
    }

    public Packet next() {
        return nextLayer;
    }

    public String text() {
        return String.format("ESP: spi:%d, seq:%d\n",
                Utils.bytes2Int(data_buf, start),
                Utils.bytes2Int(data_buf, start+4)
        );
    }

    public void print() {
        System.out.print(text());
    }

    public void printAll() {
        print();
        if(nextLayer != null)
            nextLayer.print();
        else
            System.out.println();
    }

    public static void main(String[] args) {
        TEST.timer.start();
        Pcap pcap = new Pcap(TEST.getDir() + "ipsec.pcap");
        pcap.unpack();
        TEST.timer.end("Unpack");

        Packet pcap_hdr = pcap.pcapHdr;
        System.out.println("MAGIC: " + pcap_hdr.field(PcapHdr.MAGIC));
        System.out.println("V_MAJOR: " + pcap_hdr.field(PcapHdr.V_MAJOR));
        System.out.println("V_MINOR: " + pcap_hdr.field(PcapHdr.V_MINOR));
        System.out.println("THISZONE: " + pcap_hdr.field(PcapHdr.THISZONE));
        System.out.println("SIGFIGS: " + pcap_hdr.field(PcapHdr.SIGFIGS));
        System.out.println("SNAPLEN: " + pcap_hdr.field(PcapHdr.SNAPLEN));
        System.out.println("LINKTYPE: " + pcap_hdr.field(PcapHdr.LINKTYPE));



        TEST.timer.start();
        Iterator<Packet> iter = pcap.iterator();
        Packet eth = iter.next();
        if(eth instanceof Ethernet) {
            Packet ip = eth.next();
            if(ip instanceof IPv4) {
                Packet esp = ip.next();
                if(esp instanceof ESP) {
                    System.out.println("SPI: " + esp.field(ESP.SPI));
                    System.out.println("SEQUENCE: " + esp.field(ESP.SEQUENCE));
                }
            }
        }
        TEST.timer.end("PRINT");
    }
}
