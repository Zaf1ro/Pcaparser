package com.jduan;
import java.util.Iterator;


/* http://www.networksorcery.com/enp/protocol/ieee8022.htm */
public class LLC extends Protocol {
    public final static int DSAP = 0;            /* 4b, version */
    public final static int SSAP = 1;                /* 4b, internet Header Length */
    public final static int CONTROL = 2;                /* 6b, type of service */

    private final static int LLC_LEN = 0;
    private int start;

    LLC(byte[] __buf, int __start) {
        assert (__buf != null);
        data_buf = __buf;
        start = __start;
        nextLayer = link();
    }

    private Protocol link() {
        return null;
    }

    public String field(int id) {
        assert (data_buf != null);
        switch (id) {
            case DSAP:
                return Utils.bytes2Hex(data_buf, start, 1);
            case SSAP:
                return Utils.bytes2Hex(data_buf, start+1, 1);
            case CONTROL:
                return Utils.bytes2Hex(data_buf, start+2, 1);
            default:
                return null;
        }
    }

    public String type() {
        return "LLC";
    }

    public String text() {
        return String.format("LLC:\t DSAP:%s, SSAP:%s",
                field(LLC.DSAP),
                field(LLC.SSAP)
        );
    }

    public static void main(String[] args) {
        TEST.timer.start();
        Pcap pcap = new Pcap(TEST.getDir() + "llc.pcap");
        pcap.unpack();
        TEST.timer.end("Unpack");

        TEST.timer.start();
        Iterator<Protocol> iter = pcap.iterator();
        Protocol eth = iter.next();
        if (eth instanceof Ethernet) {
            Protocol llc = eth.next();
            if (llc instanceof LLC) {
                System.out.println("DSAP: " + llc.field(LLC.DSAP));
                System.out.println("SSAP: " + llc.field(LLC.SSAP));
                System.out.println("CONTROL: " + llc.field(LLC.CONTROL));
            }
        }
        TEST.timer.end("PRINT");
    }
}
