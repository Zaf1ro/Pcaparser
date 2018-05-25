package com.jduan.pcap;


/**
 * Parsing RTP protocol. This class provides an API compatible
 * with {@link Protocol}. For more information of RTP protocol,
 * see http://www.networksorcery.com/enp/protocol/rtp.htm
 *
 * @author  Jiaxu Duan
 * @since   5/12/18
 * @see     com.jduan.pcap.Protocol
 */
public final class RTP extends Protocol {
    public final static int VERSION = 0;    /* 2b, version number */
    public final static int P = 1;          /* 1b, if set, it contains additional padding */
    public final static int X = 2;          /* 1b, if set, it contains one more header extension */
    public final static int CC = 3;         /* 4b, the number of CSRC identifiers */
    public final static int M = 4;          /* 1b, the interpretation of the marker */
    public final static int PT = 5;         /* 7b, the format of RTP payload */
    public final static int SEQUENCE = 6;   /* the squence number incremented by one for each RTP data */
    public final static int TIMESTAMP = 7;  /* 4, derived from a clock that increments monotonically */
    public final static int SSRC = 8;       /* 4, random number to identify the synchronization source */

    private int start;

    RTP(byte[] __buf, int __start) {
        assert (__buf != null);
        data_buf = __buf;
        start = __start;
    }

    @Override
    public String field(int id) {
        assert (data_buf != null);
        switch (id) {
            case VERSION:
                return Integer.toString((data_buf[start] >>> 6) & 0x03);
            case P:
                return Integer.toString((data_buf[start] >>> 5) & 0x01);
            case X:
                return Integer.toString((data_buf[start] >>> 4) & 0x01);
            case CC:
                return Integer.toString(data_buf[start] & 0x0F);
            case M:
                return Integer.toString((data_buf[start+1] >>> 7) & 0x01);
            case PT:
                return Integer.toString(data_buf[start+1] & 0x7F);
            case SEQUENCE:
                return Short.toString(Utils.bBytes2Short(data_buf, start+2));
            case TIMESTAMP:
                return Integer.toString(Utils.bBytes2Int(data_buf, start+4));
            case SSRC:
                return Integer.toString(Utils.bBytes2Int(data_buf, start+8));
            default:
                return null;
        }
    }

    @Override
    public String type() {
        return "RTP";
    }

    @Override
    public String text() {
        return String.format("RTP:\t VERSION:%s",
                field(RTP.VERSION)
        );
    }
}
