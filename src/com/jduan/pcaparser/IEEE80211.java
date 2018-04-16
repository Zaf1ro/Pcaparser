package com.jduan.pcaparser;
import java.util.Iterator;


/* https://witestlab.poly.edu/blog/802-11-wireless-lan-2/ */
public final class IEEE80211 extends Protocol {
    public final static int FRAME_CONTROL = 1;  /* 2, public final static int */
    public final static int DURATION = 2;       /* 2, microseconds to reserve link */
    public final static int ADDR1 = 3;          /* 6, immediate receiver */
    public final static int ADDR2 = 4;          /* 6, immediate sender */
    public final static int ADDR3 = 5;          /* 6, forward to */
    public final static int SEQUENCE = 6;       /* 2, Sequence Control field */

    private final static int IEEE80211_LEN = 24;
    private PktHdr pktHdr;

    IEEE80211() {
        pktHdr = new PktHdr();
        data_buf = new byte[pktHdr.getDataLen()];
        Pcap.reader.fill(data_buf);
    }

    public String field(int id) {
        switch (id) {
            case FRAME_CONTROL:
                return String.format("0x%04x", Utils.bytes2Short(data_buf, 0));
            case DURATION:
                return Short.toString(Utils.bytes2Short(data_buf, 2));
            case ADDR1:
                return Utils.bytes2MAC(data_buf, 4);
            case ADDR2:
                return Utils.bytes2MAC(data_buf, 10);
            case ADDR3:
                return Utils.bytes2MAC(data_buf, 16);
            case SEQUENCE:
                return String.format("0x%04x", Utils.bytes2Short(data_buf, 22));
            default:
                return pktHdr.field(id);
        }
    }

    public String type() {
        return "IEEE802.11";
    }

    public String text() {
        return String.format("Ethernet:\t ADDR1:%s, ADDR2:%s, ADDR3:%s",
                field(IEEE80211.ADDR1),
                field(IEEE80211.ADDR2),
                field(IEEE80211.ADDR3)
        );
    }

    public static void main(String[] args) {
        TEST.timer.start();
        Pcap pcap = new Pcap(TEST.getDir() + "ieee802_11.pcap");
        pcap.unpack();
        TEST.timer.end("Unpack");

        TEST.timer.start();

        Iterator<Protocol> iter = pcap.iterator();
        Protocol ieee802_11 = iter.next();
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
