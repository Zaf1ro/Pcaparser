package com.jduan.pcap;


// TODO: decode OSPF message
/**
 * Parsing OSPF protocol. This class provides an API compatible
 * with {@link Protocol}. For more information of OSPF protocol,
 * see http://www.tcpipguide.com/free/t_OSPFMessageFormats.htm
 *
 * @author  Jiaxu Duan
 * @since   5/12/18
 * @see     com.jduan.pcap.Protocol
 */
public class OSPF extends Protocol {
    public final static int VERSION = 0;        /* 1, Version Number */
    public final static int TYPE = 1;           /* 1, type of OSPF message */
    public final static int PACKET_LENGTH = 2;  /* 2, Protocol Length */
    public final static int ROUTER_ID = 3;      /* 4, The ID of the router */
    public final static int AREA_ID = 4;        /* 4, An identification of the OSPF area */
    public final static int CHECKSUM = 5;       /* 2, standard IP checksum */
    public final static int AUTYPE = 6;         /* 2, authentication type */
    public final static int AUTHENTICATION = 7; /* 8, authentication of the message */

    private int start;

    OSPF(byte[] __buf, int __start) {
        assert (__buf != null);
        data_buf = __buf;
        start = __start;
    }

    @Override
    public String field(int id) {
        assert (data_buf != null);
        switch (id) {
            case VERSION:
                return Byte.toString(data_buf[start]);
            case TYPE:
                return Byte.toString(data_buf[start + 1]);
            case PACKET_LENGTH:
                return Short.toString(Utils.bBytes2Short(data_buf, start + 2));
            case ROUTER_ID:
                return Utils.bytes2IPv4(data_buf, start + 4);
            case AREA_ID:
                return Utils.bytes2IPv4(data_buf, start + 8);
            case CHECKSUM:
                return String.format("0x%02x", Utils.bBytes2Short(data_buf, start + 12));
            case AUTYPE:
                return Short.toString(Utils.bBytes2Short(data_buf, start + 14));
            case AUTHENTICATION:
                return Utils.bytes2Hex(data_buf, start + 16, 8);
            default:
                return null;
        }
    }

    @Override
    public String type() {
        return "OSPF";
    }

    @Override
    public String text() {
        return String.format("OSPF:\t ROUTER ID:%s, AREA ID:%s",
                field(OSPF.ROUTER_ID),
                field(OSPF.AREA_ID)
        );
    }
}
