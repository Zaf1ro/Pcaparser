package com.jduan.pcap;


/**
 * Parsing IPv6 protocol. This class provides an API compatible
 * with {@link Protocol}. For more information of IPv6 protocol,
 * see https://en.wikipedia.org/wiki/IPv6_packet
 *
 * @author  Jiaxu Duan
 * @since   5/12/18
 * @see     com.jduan.pcap.Protocol
 */
public final class IPv6 extends Protocol {
    public final static int VERSION = 1;           /* 4b, version */
    public final static int TRAFFI_CLASS = 2;      /* 1, hold two values: DS, ECN */
    public final static int FLOW_LABEL = 3;        /* 20b,  label a set of protocols belonging to a flow */
    public final static int PAYLOAD_LENGTH = 4;    /* 2, length of data */
    public final static int NEXT_HEADER = 5;       /* 1, type of the next header */
    public final static int HOP_LIMIT = 6;         /* 1, same as TTL */
    public final static int SRC_ADDR = 7;          /* 16, source address */
    public final static int DST_ADDR = 8;          /* 16, destination address */

    private int payload_len;
    private int start;

    IPv6(byte[] __buf, int __start) {
        assert (__buf != null);
        data_buf = __buf;
        start = __start;
        payload_len = Utils.bBytes2Short(data_buf, start + 4);
        nextLayer = link();
    }

    private Protocol link() {
        int type = data_buf[start + 6];   // next header
        switch (type) {
            case 0x03A:
                return new ICMP6(data_buf, data_buf.length - payload_len);
            case 0x06:
                return new TCP(data_buf, data_buf.length - payload_len);
            case 0x11:
                nextLayer = new UDP(data_buf, data_buf.length - payload_len);
            default:
                return null;
        }
    }

    @Override
    public String field(int id) {
        assert (data_buf != null);
        switch (id) {
            case VERSION:
                return Integer.toString(data_buf[start] >>> 4);
            case TRAFFI_CLASS:
                return String.format("0x%02x", (Utils.bBytes2Short(data_buf, start) >>> 4) & 0xFF);
            case FLOW_LABEL:
                return String.format("0x%05x", (data_buf[start + 1] >>> 4) << 16 + Utils.bBytes2Short(data_buf, start + 2));
            case PAYLOAD_LENGTH:
                return Short.toString(Utils.bBytes2Short(data_buf, start + 4));
            case NEXT_HEADER:
                return Byte.toString(data_buf[start + 6]);
            case HOP_LIMIT:
                return Byte.toString(data_buf[start + 7]);
            case SRC_ADDR:
                return Utils.bytes2IPv6(data_buf, start + 8);
            case DST_ADDR:
                return Utils.bytes2IPv6(data_buf, start + 24);
            default:
                return null;
        }
    }

    @Override
    public String type() {
        return "IPv6";
    }

    @Override
    public String text() {
        return String.format("IPv6:\t SRC IP:%s, DST IP:%s",
                field(IPv6.SRC_ADDR),
                field(IPv6.DST_ADDR)
        );
    }
}
