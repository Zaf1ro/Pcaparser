package com.jduan.pcap;


/**
 * Parsing IEEE 802.3 protocol. This class provides an API compatible
 * with {@link Protocol}. For more information of IEEE 802.3 protocol,
 * see https://en.wikipedia.org/wiki/IEEE_802.3
 *
 * @author  Jiaxu Duan
 * @since   5/12/18
 * @see     com.jduan.pcap.Protocol
 */

public final class IEEE8023 extends Protocol {
    public final static int DHOST = 0;      /* 6, Destination host address */
    public final static int SHOST = 6;      /* 6, Source host address */
    public final static int LENGTH = 12;    /* 2, Type of ethernet */

    private final static int ETH_LEN = 14;

    IEEE8023(byte[] __buf) {
        assert (__buf != null);
        data_buf = __buf;
        nextLayer = link();
    }

    private Protocol link() {
        return new LLC(data_buf, ETH_LEN);
    }

    @Override
    public String type() {
        return "IEEE 802.3";
    }

    @Override
    public String text() {
        return String.format("IEEE 802.3:\t SHOST:%s, DHOST:%s",
                field(EthernetII.SHOST),
                field(EthernetII.DHOST)
        );
    }

    @Override
    public String field(int id) {
        switch (id) {
            case DHOST:
                return Utils.bytes2MAC(data_buf, 0);
            case SHOST:
                return Utils.bytes2MAC(data_buf, 6);
            case LENGTH:
                return Short.toString(Utils.bBytes2Short(data_buf, 12));
            default:
                return null;
        }
    }
}
