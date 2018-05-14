package com.jduan.pcap;


/**
 * Parsing ICMP6 protocol. This class provides an API compatible
 * with {@link Protocol}. For more information of ICMP6 protocol,
 * see en.wikipedia.org/wiki/Internet_Control_Message_Protocol_for_IPv6
 *
 * @author  Jiaxu Duan
 * @since   5/12/18
 * @see     com.jduan.pcap.Protocol
 */
public final class ICMP6 extends Protocol {
    public final static int TYPE = 0;            /* 1, ICMP type */
    public final static int CODE = 1;            /* 1, ICMP subtype */
    public final static int CHECKSUM = 2;        /* 2, Error checking data */

    private final static int ICMP6_LEN = 20;
    private int start;

    ICMP6(byte[] __buf, int __start) {
        assert (__buf != null);
        data_buf = __buf;
        start = __start;
    }

    @Override
    public String field(int id) {
        assert (data_buf != null);
        switch (id) {
            case TYPE:
                return Integer.toString(data_buf[start] & 0xFF);
            case CODE:
                return Integer.toString(data_buf[start + 1] & 0xFF);
            case CHECKSUM:
                return Utils.bytes2Hex(data_buf, start + 2, 2);
            default:
                return null;
        }
    }

    @Override
    public String type() {
        return "ICMP6";
    }

    @Override
    public String text() {
        return String.format("ICMP6:\t TYPE:%s, CODE:%s",
                field(ICMP6.TYPE),
                field(ICMP6.CODE)
        );
    }
}
