package com.jduan.pcap;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.ConcurrentModificationException;
import java.util.Iterator;
import java.util.NoSuchElementException;

// TODO: get data from network adaptor
/**
 * Parsing Pcap file header. For more information of Pcap file header,
 * see https://wiki.wireshark.org/Development/LibpcapFileFormat#Global_Header
 *
 * @author  Jiaxu Duan
 * @since   5/12/18
 * @see     com.jduan.pcap.Protocol
 */
public class Pcap {
    public final static int MAGIC = 1;      /* 32, magic number */
    public final static int V_MAJOR = 2;    /* 16, major version number */
    public final static int V_MINOR = 3;    /* 16, minor version number */
    public final static int THISZONE = 4;   /* 32, GMT */
    public final static int SIGFIGS = 5;    /* 32, accuracy of timestamps */
    public final static int SNAPLEN = 6;    /* 32, max length pf captured protocols */
    public final static int LINKTYPE = 7;   /* 32, data line type */

    /* Type of datalink layer */
    private final static int DLT_ETHERNET = 0x0001;     /* Ethernet -> EthernetII, IEEE802.3 */
    private final static int DLT_PPP = 0x0009;          /* Point-to-Point Protocol */
    private final static int DLT_IEEE802_11 = 0x0069;   /* IEEE 802.11 wireless LAN */

    private final static int PCAPHDR_LEN = 24;

    static Reader reader;
    private static ArrayList<Protocol> packets;
    private byte[] pcapHdr_buf;

    public Pcap() {
        // get data from network
    }

    public Pcap(String pcap_path) {
        reader = new Reader(pcap_path);
        packets = new ArrayList<>();
//        proto_map = new HashMap<>();
    }

    public String field(int id) {
        switch (id) {
            case MAGIC:
                return Utils.bytes2Hex(pcapHdr_buf, 0, 4);
            case V_MAJOR:
                return Short.toString(Utils.lBytes2Short(pcapHdr_buf, 4));
            case V_MINOR:
                return Short.toString(Utils.lBytes2Short(pcapHdr_buf, 6));
            case THISZONE:
                return Integer.toString(Utils.lBytes2Int(pcapHdr_buf, 8));
            case SIGFIGS:
                return Integer.toString(Utils.lBytes2Int(pcapHdr_buf, 12));
            case SNAPLEN:
                return Integer.toString(Utils.lBytes2Int(pcapHdr_buf, 16));
            case LINKTYPE:
                return Integer.toString(Utils.lBytes2Int(pcapHdr_buf, 20));
            default:
                return null;
        }
    }

    public void unpack() {
        Constructor constructor = null;
        try {
            constructor = getConstructor();
        } catch (PcapException e) {
            e.printStackTrace();
        }

        while (reader.isRemaining()) {
            try {
                Protocol p = (Protocol) constructor.newInstance();
                packets.add(p);
            } catch (InvocationTargetException | IllegalAccessException | InstantiationException e) {
                e.printStackTrace();
            }
        }
    }

    public Iterator<Protocol> iterator() {
        return new PacketItr();
    }

    public Iterator<Protocol> iterator(int index) {
        return new PacketItr(index);
    }

    /* Implementation of iteration */
    private class PacketItr implements Iterator<Protocol> {
        int cursor;
        int size;

        PacketItr() {
            super();
            size = packets.size();
        }

        PacketItr(int index) {
            super();
            size = packets.size();
            cursor = index;
        }

        public boolean hasPrevious() {
            return cursor != 0;
        }

        public boolean hasNext() {
            return cursor != size;
        }

        public Protocol next() {
            int i = cursor;
            if (i >= size)
                throw new NoSuchElementException();
            if (i >= packets.size())
                throw new ConcurrentModificationException();
            ++cursor;
            return packets.get(i);
        }

        public Protocol previous() {
            int i = cursor - 1;
            if (i < 0)
                throw new NoSuchElementException();
            if (i >= packets.size())
                throw new ConcurrentModificationException();
            --cursor;
            return packets.get(i);
        }
    }

    private Constructor getConstructor() throws PcapException {
        pcapHdr_buf = new byte[PCAPHDR_LEN];
        assert (Pcap.reader != null);
        Pcap.reader.fill(pcapHdr_buf);

        /* check datalink type */
        int linktype = Utils.lBytes2Int(pcapHdr_buf, 20);
        Class cDatalink = null;
        switch (linktype) {
            case DLT_ETHERNET:
                cDatalink = Ethernet.class;
                break;
            case DLT_PPP:
                cDatalink = PPP.class;
                break;
            case DLT_IEEE802_11:
                cDatalink = IEEE80211.class;
                break;
        }

        /* unsupported type of datalink */
        assert(cDatalink != null);

        Constructor constructor = null;
        try {
            constructor = cDatalink.getDeclaredConstructor();
        } catch (NoSuchMethodException e) {
            e.printStackTrace();
        }
        return constructor;
    }
}


/**
 * Pcap Exception Class
 *
 * @author  Jiaxu Duan
 * @since   5/12/18
 * @see     Exception
 */
class PcapException extends Exception {
    public PcapException() {
        super();
    }

    public PcapException(String msg) {
        super(msg);
    }
}
