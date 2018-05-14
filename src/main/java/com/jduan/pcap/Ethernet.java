package com.jduan.pcap;


/**
 * Parsing Ether Type to define which type of Ethernet.
 * This class provides an API compatible with {@link Protocol}. For more information of Ethernet protocol,
 * see https://en.wikipedia.org/wiki/Ethernet_frame
 *
 * @author  Jiaxu Duan
 * @since   5/12/18
 * @see     com.jduan.pcap.Protocol
 */
class Ethernet extends Protocol {
    Ethernet() {
        PktHdr pktHdr = new PktHdr();
        data_buf = new byte[pktHdr.getDataLen()];
        Pcap.reader.fill(data_buf);
        nextLayer = link();
    }

    private Protocol link() {
        // TODO: add Novell Ethernet and Ethernet SNAP
        int type = Utils.bBytes2Short(data_buf, 12) & 0xFFFF;
        if(type > 1500) {
            return new EthernetII(data_buf);
        } else {
            return new IEEE8023(data_buf);
        }
    }

    @Override
    public Protocol next() {
        return nextLayer.next();
    }

    @Override
    public String field(int id) {
        return nextLayer.field(id);
    }

    @Override
    public String type() {
        return nextLayer.type();
    }

    @Override
    public String text() {
        return nextLayer.text();
    }
}
