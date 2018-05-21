package com.jduan.pcap;


/**
 * Parsing PPP protocol. This class provides an API compatible
 * with {@link Protocol}. For more information of PPP protocol,
 * see https://en.wikipedia.org/wiki/Point-to-Point_Protocol
 *
 * @author  Jiaxu Duan
 * @since   5/12/18
 * @see     com.jduan.pcap.Protocol
 */
public final class PPP extends Protocol {
    public final static int ADDR = 0;       /* 1, standard broadcast address */
    public final static int CONTROL = 1;    /* 1, unnumbered data */
    public final static int PROTOCOL = 2;   /* 2, PPP ID of embedded data */

    private PktHdr pktHdr;

    PPP() {
        pktHdr = new PktHdr();
        data_buf = new byte[pktHdr.getDataLen()];
        Pcap.reader.fill(data_buf);
    }

    @Override
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

    @Override
    public String type() {
        return "PPP";
    }

    @Override
    public String text() {
        return String.format("PPP:\t ADDR:%s\n",
                field(PPP.ADDR)
        );
    }
}
