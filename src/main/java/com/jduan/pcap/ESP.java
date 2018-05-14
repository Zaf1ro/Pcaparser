package com.jduan.pcap;


/**
 * Parsing ESP protocol. This class provides an API compatible
 * with {@link Protocol}. For more information of ESP protocol,
 * see en.wikipedia.org/wiki/IPsec#Encapsulating_Security_Payload
 *
 * @author  Jiaxu Duan
 * @since   5/12/18
 * @see     com.jduan.pcap.Protocol
 */
public class ESP extends Protocol {
    public final static int SPI = 0;        /* 4, Security Parameters Index */
    public final static int SEQUENCE = 1;   /* 4, A sequence number to protect against replay attacks */

    private final static int ESP_LEN = 8;
    private int start;

    ESP(byte[] __buf, int __start) {
        assert (__buf != null);
        data_buf = __buf;
        start = __start;
    }

    @Override
    public String field(int id) {
        assert (data_buf != null);
        switch (id) {
            case SPI:
                return Utils.bytes2Hex(data_buf, start, 4);
            case SEQUENCE:
                return Integer.toString(Utils.bBytes2Int(data_buf, start + 4));
            default:
                return null;
        }
    }

    @Override
    public String type() {
        return "ESP";
    }

    @Override
    public String text() {
        return String.format("ESP:\t SPI:%s, SEQ:%s",
                field(ESP.SPI),
                field(ESP.SEQUENCE)
        );
    }
}
