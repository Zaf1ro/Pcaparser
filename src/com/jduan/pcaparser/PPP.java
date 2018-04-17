package com.jduan.pcaparser;

import java.util.Iterator;


/* https://en.wikipedia.org/wiki/Point-to-Point_Protocol#Structure_of_a_PPP_frame */
public class PPP extends Protocol {
    public final static int ADDR = 0;       /* 1, standard broadcast address */
    public final static int CONTROL = 1;    /* 1, unnumbered data */
    public final static int PROTOCOL = 2;   /* 2, PPP ID of embedded data */

    private PktHdr pktHdr;
    private final static int PPP_LEN = 4;

    PPP() {
        pktHdr = new PktHdr();
        data_buf = new byte[pktHdr.getDataLen()];
        Pcap.reader.fill(data_buf);
    }

    public String field(int id) {
        switch (id) {
            case ADDR:
                return String.format("0x%02x", data_buf[0]);
            case CONTROL:
                return String.format("0x%02x", data_buf[1]);
            case PROTOCOL:
                return Utils.bytes2Hex(data_buf, 2, 2);
            default:
                return pktHdr.field(id);
        }
    }

    public String type() {
        return "PPP";
    }

    public String text() {
        return String.format("PPP:\t ADDR:%s\n",
                field(PPP.ADDR)
        );
    }

    public static void main(String[] args) {
        TEST.timer.start();
        Pcap pcap = new Pcap(TEST.getDir() + "ppp.pcap");
        pcap.unpack();
        TEST.timer.end("Unpack");

        TEST.timer.start();

        Iterator<Protocol> iter = pcap.iterator();
        Protocol ppp = iter.next();
        if (ppp instanceof PPP) {
            System.out.println("ADDR: " + ppp.field(PPP.ADDR));
            System.out.println("CONTROL: " + ppp.field(PPP.CONTROL));
            System.out.println("PROTOCOL: " + ppp.field(PPP.PROTOCOL));
        }

        TEST.timer.end("PRINT");
    }
}
