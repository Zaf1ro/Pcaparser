package com.jduan.pcaparser;
import java.util.Iterator;


/* https://en.wikipedia.org/wiki/Point-to-Point_Protocol#Structure_of_a_PPP_frame */
public class PPP extends PktHdr {
    public final static int ADDR = 0;       /* 1, standard broadcast address */
    public final static int CONTROL = 1;    /* 1, unnumbered data */
    public final static int PROTOCOL = 2;   /* 2, PPP ID of embedded data */

    private final static int PPP_LEN = 4;

    private byte[] data_buf;
    private Packet nextLayer = null;    /* no next layer */

    PPP() {
        super();
        data_buf = new byte[getDataLen()];
        Pcap.reader.fill(data_buf);
    }

    public String field(int id) {
        switch (id) {
            case ADDR:
                return String.format("%x", data_buf[0]);
            case CONTROL:
                return String.format("%x", data_buf[1]);
            case PROTOCOL:
                return String.format("%x", Utils.bytes2Short(data_buf, 2));
            default:
                return null;
        }
    }

    public String type() {
        return "PPP";
    }

    public Packet next() {
        return nextLayer;
    }

    public String text() {
        return String.format("PPP: addr:%x, control:%x, proto:%x\n",
                data_buf[0],
                data_buf[1],
                Utils.bytes2Short(data_buf, 2)
        );
    }

    public void print() {
        System.out.print(text());
    }

    public void printAll() {
        print();
        if(nextLayer != null)
            nextLayer.printAll();
        else
            System.out.println();
    }

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
