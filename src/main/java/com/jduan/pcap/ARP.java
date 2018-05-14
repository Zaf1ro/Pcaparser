package com.jduan.pcap;


/**
 * Parsing ARP protocol. This class provides an API compatible
 * with {@link Protocol}. For more information of ARP protocol,
 * see https://en.wikipedia.org/wiki/Address_Resolution_Protocol
 *
 * @author  Jiaxu Duan
 * @since   5/12/18
 * @see     com.jduan.pcap.Protocol
 */
public final class ARP extends Protocol {
    public final static int HTYPE = 1;     /* 2, Type of network protocol type */
    public final static int PTYPE = 2;     /* 2, Type of internetwork protocol */
    public final static int HLEN = 3;      /* 1, Hardware address length */
    public final static int PLEN = 4;      /* 1, Protocol address length */
    public final static int OPERATION = 5; /* 2, Operation */
    public final static int SHA = 6;       /* 6, Sender hardware address  */
    public final static int SPA = 7;       /* 4, Sender protocol address */
    public final static int THA = 8;       /* 6, Target hardware address */
    public final static int TPA = 9;       /* 4, Target protocol address */

    private final static int ARP_LEN = 26;
    private int start;

    ARP(byte[] __buf, int __start) {
        assert (__buf != null);
        data_buf = __buf;
        start = __start;
    }

    @Override
    public String field(int id) {
        switch (id) {
            case HTYPE:
                return Short.toString(Utils.bBytes2Short(data_buf, start));
            case PTYPE:
                return Utils.bytes2Hex(data_buf, start + 2, 2);
            case HLEN:
                return Byte.toString(data_buf[start + 4]);
            case PLEN:
                return Byte.toString(data_buf[start + 5]);
            case OPERATION:
                return Short.toString(Utils.bBytes2Short(data_buf, start + 6));
            case SHA:
                return Utils.bytes2MAC(data_buf, start + 8);
            case SPA:
                return Utils.bytes2IPv4(data_buf, start + 14);
            case THA:
                return Utils.bytes2MAC(data_buf, start + 18);
            case TPA:
                return Utils.bytes2IPv4(data_buf, start + 24);
            default:
                return null;
        }
    }

    @Override
    public String type() {
        return "ARP";
    }

    @Override
    public String text() {
        return String.format("ARP:\t SHA:%s, SPA:%s",
                field(ARP.SHA),
                field(ARP.SPA)
        );
    }
}
