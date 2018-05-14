package com.jduan.pcap;


/**
 * Parsing ICMP protocol. This class provides an API compatible
 * with {@link Protocol}. For more information of ICMP protocol,
 * see en.wikipedia.org/wiki/Internet_Control_Message_Protocol
 *
 * @author  Jiaxu Duan
 * @since   5/12/18
 * @see     com.jduan.pcap.Protocol
 */
public final class ICMP extends Protocol {
    public final static int TYPE = 0;            /* 1, ICMP type */
    public final static int CODE = 1;            /* 1, ICMP subtype */
    public final static int CHECKSUM = 2;        /* 2, Error checking data */

    private final static int ICMP_LEN = 20;
    private int start;

    ICMP(byte[] __buf, int __start) {
        assert (__buf != null);
        data_buf = __buf;
        start = __start;
    }

    @Override
    public String field(int id) {
        assert (data_buf != null);
        switch (id) {
            case TYPE:
                return Byte.toString(data_buf[start]);
            case CODE:
                return Byte.toString(data_buf[start + 1]);
            case CHECKSUM:
                return Utils.bytes2Hex(data_buf, start + 2, 2);
            default:
                return null;
        }
    }

    @Override
    public String type() {
        return "ICMP";
    }

    @Override
    public String text() {
        return String.format("ICMP:\t TYPE:%s, CODE:%s",
                field(ICMP.TYPE),
                field(ICMP.CODE)
        );
    }
}
