package com.jduan.pcap;
import java.util.Iterator;


/**
 * Parsing LLC protocol. This class provides an API compatible
 * with {@link Protocol}. For more information of LLC protocol,
 * see http://www.networksorcery.com/enp/protocol/ieee8022.htm
 *
 * @author  Jiaxu Duan
 * @since   5/12/18
 * @see     com.jduan.pcap.Protocol
 */
public class LLC extends Protocol {
    public final static int DSAP = 0;       /* 4b, version */
    public final static int SSAP = 1;       /* 4b, internet Header Length */
    public final static int CONTROL = 2;    /* 6b, type of service */

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

    @Override
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

    @Override
    public String type() {
        return "Logical Link Control";
    }

    @Override
    public String text() {
        return String.format("Logical Link Control:\t DSAP:%s, SSAP:%s",
                field(LLC.DSAP),
                field(LLC.SSAP)
        );
    }

    public static void main(String[] args) {
        Pcap pcap = new Pcap("llc.pcap");
        pcap.unpack();

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
    }
}
