package com.jduan.pcap;
import java.util.Iterator;


/**
 * Parsing AH protocol. This class provides an API compatible
 * with {@link Protocol}. For more information of AH protocol,
 * see http://www.networksorcery.com/enp/protocol/ah.htm
 *
 * @author  Jiaxu Duan
 * @since   5/12/18
 * @see     com.jduan.pcap.Protocol
 */
public final class AH extends Protocol {
    public final static int NEXT = 0;       /* 1, the next encapsulated protocol */
    public final static int LENGTH = 1;     /* 1, size of AH header */
    public final static int SPI = 2;        /* 4, a pseudo random value used to identify */
    public final static int SEQUENCE = 3;   /* 4, sequence number */
    public final static int ICV = 4;        /* variable, contains a multiple of 32bit words */

    private int ICV_LEN;
    private int start;

    AH(byte[] __buf, int __start) {
        assert(__buf != null);
        data_buf = __buf;
        start = __start;
        ICV_LEN = ((data_buf[start+1] & 0xFF) - 1)  * 4;
        nextLayer = link();
    }

    private Protocol link() {
        return null;
    }

    @Override
    public String field(int id) {
        assert (data_buf != null);
        switch (id) {
            case NEXT:
                return Byte.toString(data_buf[start]);
            case LENGTH:
                return Byte.toString(data_buf[start+1]);
            case SPI:
                return Utils.bytes2Hex(data_buf, start+4, 4);
            case SEQUENCE:
                return Utils.bytes2Hex(data_buf, start+8, 4);
            case ICV:
                return Utils.bytes2Hex(data_buf, start+12, ICV_LEN);
            default:
                return null;
        }
    }

    @Override
    public String type() {
        return "Authentication Header";
    }

    @Override
    public String text() {
        return String.format("AH:\t SPI:%s, SEQUENCE:%s",
                field(AH.SPI),
                field(AH.SEQUENCE)
        );
    }
}
