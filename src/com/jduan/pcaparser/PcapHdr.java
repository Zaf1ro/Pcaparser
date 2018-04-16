package com.jduan.pcaparser;


/* https://wiki.wireshark.org/Development/LibpcapFileFormat#Global_Header */
public class PcapHdr implements Packet {
    public final static int MAGIC = 1;      /* 32, magic number */
    public final static int V_MAJOR = 2;    /* 16, major version number */
    public final static int V_MINOR = 3;    /* 16, minor version number */
    public final static int THISZONE = 4;   /* 32, GMT */
    public final static int SIGFIGS = 5;    /* 32, accuracy of timestamps */
    public final static int SNAPLEN = 6;    /* 32, max length pf captured packets */
    public final static int LINKTYPE = 7;   /* 32, data line type */

    private final static int pcapHdr_len = 24;

    private byte[] pcapHdr_buf;

    PcapHdr() {
        pcapHdr_buf = new byte[pcapHdr_len];
        assert Pcap.reader != null;
        Pcap.reader.fill(pcapHdr_buf);
    }

    public String field(int id) {
        switch (id) {
            case MAGIC:
                return Utils.bytes2Hex(pcapHdr_buf, 0, 4);
            case V_MAJOR:
                return Short.toString(Utils.bytes2Short(pcapHdr_buf, 4));
            case V_MINOR:
                return Short.toString(Utils.bytes2Short(pcapHdr_buf, 6));
            case THISZONE:
                return Integer.toString(Utils.bytes2Int(pcapHdr_buf, 8));
            case SIGFIGS:
                return Integer.toString(Utils.bytes2Int(pcapHdr_buf, 12));
            case SNAPLEN:
                return Integer.toString(Utils.bytes2Int(pcapHdr_buf, 16));
            case LINKTYPE:
                return Integer.toString(Utils.bytes2Int(pcapHdr_buf, 20));
            default:
                return null;
        }
    }

    int get_linktype() {
        return Utils.bytes2Int(pcapHdr_buf, 20);
    }

    public String type() {
        return "Pcap Header";
    }

    public Packet next() {
        return null;
    }
    
    public String text() {
        return String.format("Pcap Header: version:%d.%d, snaplen:%d",
                Utils.bytes2Short(pcapHdr_buf, 4),
                Utils.bytes2Short(pcapHdr_buf, 6),
                Utils.bytes2Int(pcapHdr_buf, 16)
        );
    }
    
    public void print() {
        System.out.println(text());
    }

    public void printAll() {
        print();
    }

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

