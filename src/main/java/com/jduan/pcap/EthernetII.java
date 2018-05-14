package com.jduan.pcap;

/**
 * Parsing Ethernet II protocol. This class
 * provide an API compatible with {@link Protocol}.
 * For more information of Ethernet protocol,
 * see https://en.wikipedia.org/wiki/Ethernet_frame#Ethernet_II
 *
 * @author Jiaxu Duan
 * @since 5/13/18
 */
public class EthernetII extends Protocol {
    public final static int DHOST = 0;      /* 6, Destination host address */
    public final static int SHOST = 6;      /* 6, Source host address */
    public final static int ETH_TYPE = 12;  /* 2, Type of ethernet */

    private final static int ETH_LEN = 14;

    EthernetII(byte[] __buf) {
        assert (__buf != null);
        data_buf = __buf;
        nextLayer = link();
    }

    private Protocol link() {
        int type = Utils.bBytes2Short(data_buf, 12) & 0xFFFF;
        switch (type) {
            case 0x0800:
                return new IPv4(data_buf, ETH_LEN);
            case 0x86DD:
                return new IPv6(data_buf, ETH_LEN);
            case 0x0806:
                return new ARP(data_buf, ETH_LEN);
            default:
                return null;
        }
    }

    @Override
    public String field(int id) {
        switch (id) {
            case DHOST:
                return Utils.bytes2MAC(data_buf, 0);
            case SHOST:
                return Utils.bytes2MAC(data_buf, 6);
            case ETH_TYPE:
                return String.format("0x%04x", Utils.bBytes2Short(data_buf, 12));
            default:
                return null;
        }
    }

    @Override
    public String type() {
        return "Ethernet II";
    }

    @Override
    public String text() {
        return String.format("Ethernet II:\t SHOST:%s, DHOST:%s",
                field(EthernetII.SHOST),
                field(EthernetII.DHOST)
        );
    }
}
