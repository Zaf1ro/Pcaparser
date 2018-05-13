package com.jduan.pcap;

import java.util.Iterator;


/* https://en.wikipedia.org/wiki/IPsec#Encapsulating_Security_Payload */
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

    public String type() {
        return "ESP";
    }

    public String text() {
        return String.format("ESP:\t SPI:%s, SEQ:%s",
                field(ESP.SPI),
                field(ESP.SEQUENCE)
        );
    }

    public static void main(String[] args) {
        Pcap pcap = new Pcap("ipsec.pcap");
        pcap.unpack();
        Iterator<Protocol> iter = pcap.iterator();
        Protocol eth = iter.next();
        if (eth instanceof Ethernet) {
            Protocol ip = eth.next();
            if (ip instanceof IPv4) {
                Protocol esp = ip.next();
                if (esp instanceof ESP) {
                    System.out.println("SPI: " + esp.field(ESP.SPI));
                    System.out.println("SEQUENCE: " + esp.field(ESP.SEQUENCE));
                }
            }
        }
    }
}