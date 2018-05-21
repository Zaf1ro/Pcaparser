package com.jduan.pcap;


/**
 * Parsing RIP protocol. This class provides an API compatible
 * with {@link Protocol}. For more information of RIP protocol,
 * see http://cs.baylor.edu/~donahoo/tools/hacknet/original/Rip/techni.htm
 *
 * @author  Jiaxu Duan
 * @since   5/12/18
 * @see     com.jduan.pcap.Protocol
 */
public final class RIP extends Protocol {
    public final static int COMMAND = 0;    /* 1, packet type */
    public final static int VERSION = 1;    /* 1, RIP version number */
    public final static int AFI = 2;        /* 2, when it is 2, it represents IP */
    public final static int IADDR = 3;      /* 4-8, the destination IP address */
    public final static int METRIC = 4;     /* 4, the hop count to its destination */

    private int start;

    RIP(byte[] __buf, int __start) {
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
            case COMMAND:
                return Byte.toString(data_buf[start]);
            case VERSION:
                return Byte.toString(data_buf[start+1]);
            case AFI:
                return Short.toString(Utils.bBytes2Short(data_buf, start+4));
            case IADDR:
                return Utils.bytes2IPv4(data_buf, start+8);
            case METRIC:
                return Integer.toString(Utils.bBytes2Int(data_buf, start+20));
            default:
                return null;
        }
    }

    @Override
    public String type() {
        return "RIP";
    }

    @Override
    public String text() {
        return String.format("RIP:\t COMMAND:%s, VERSION:%s",
                field(RIP.COMMAND),
                field(RIP.VERSION)
        );
    }
}
