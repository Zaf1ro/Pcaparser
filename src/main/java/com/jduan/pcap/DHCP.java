package com.jduan.pcap;
import java.util.Iterator;


/**
 * Parsing DHCP protocol. This class provides an API compatible
 * with {@link Protocol}. For more information of DHCP protocol,
 * see https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol
 *
 * @author  Jiaxu Duan
 * @since   5/12/18
 * @see     com.jduan.pcap.Protocol
 */
public final class DHCP extends Protocol {
    public final static int OP = 0;         /* 1, the general type of message */
    public final static int HTYPE = 1;      /* 1, the type of hardware */
    public final static int HLEN = 2;       /* 1, Hardware Address Length */
    public final static int HOPS = 3;       /* 1, incremented by relay agent */
    public final static int XID = 4;        /* 4, An identification field generated by the client */
    public final static int SECS = 5;       /* 2, seconds since client began to acquire or renew a lease */
    public final static int FLAGS = 6;      /* 2, contains just one flag subfield */
    public final static int CIADDR = 7;     /* 4, Client IP Address */
    public final static int YIADDR = 8;     /* 4, The IP Address that server assign to client */
    public final static int SIADDR = 9;     /* 4, Server IP Address */
    public final static int GIADDR = 10;    /* 4, Gateway IP Address */
    public final static int CHADDR = 11;    /* 16, Client Hardware Address */
    public final static int SNAME = 12;     /* 64, Server Name */
    public final static int FNAME = 13;     /* 128, Boot Filename */
    public final static int OPTIONS = 14;   /* , several parameters required for DHCP operation */

    private int start;

    DHCP(byte[] __buf, int __start) {
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
            case OP:
                return Byte.toString(data_buf[start]);
            case HTYPE:
                return Utils.bytes2Hex(data_buf, start+1, 1);
            case HLEN:
                return Byte.toString(data_buf[start+2]);
            case HOPS:
                return Byte.toString(data_buf[start+3]);
            case XID:
                return Utils.bytes2Hex(data_buf, start+4, 4);
            case SECS:
                return Short.toString(Utils.bBytes2Short(data_buf, start+8));
            case FLAGS:
                return Utils.bytes2Hex(data_buf, start+10, 2);
            case CIADDR:
                return Utils.bytes2IPv4(data_buf, start+12);
            case YIADDR:
                return Utils.bytes2IPv4(data_buf, start+16);
            case SIADDR:
                return Utils.bytes2IPv4(data_buf, start+20);
            case GIADDR:
                return Utils.bytes2IPv4(data_buf, start+24);
            case CHADDR:
                return Utils.bytes2MAC(data_buf, start+28);
            case SNAME:
                return Utils.bytes2Hex(data_buf, start+44, 64);
            case FNAME:
                return Utils.bytes2Hex(data_buf, start+108, 128);
            case OPTIONS:
                return Utils.bytes2Hex(data_buf, start+236, data_buf.length-start-240);
            default:
                return null;
        }
    }

    @Override
    public String type() {
        return "DHCP";
    }

    @Override
    public String text() {
        return String.format("DHCP:\t OPCODE:%s, TRANSACTION ID:%s",
                field(DHCP.OP),
                field(DHCP.XID)
        );
    }
}
