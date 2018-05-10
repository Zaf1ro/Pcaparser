package com.jduan;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.ConcurrentModificationException;
import java.util.Iterator;
import java.util.NoSuchElementException;


/* https://wiki.wireshark.org/Development/LibpcapFileFormat#Global_Header */
public class Pcap {
    public final static int MAGIC = 1;      /* 32, magic number */
    public final static int V_MAJOR = 2;    /* 16, major version number */
    public final static int V_MINOR = 3;    /* 16, minor version number */
    public final static int THISZONE = 4;   /* 32, GMT */
    public final static int SIGFIGS = 5;    /* 32, accuracy of timestamps */
    public final static int SNAPLEN = 6;    /* 32, max length pf captured protocols */
    public final static int LINKTYPE = 7;   /* 32, data line type */

    private final static int DLT_EN10MB = 0x0001;       /* IEEE 802.3 Ethernet */
    private final static int DLT_PPP = 0x0009;          /* Point-to-Point Protocol */
    private final static int DLT_IEEE802_11 = 0x0069;   /* IEEE 802.11 wireless LAN */

    private final static int PCAPHDR_LEN = 24;

    static Reader reader;
    private static ArrayList<Protocol> packets;
    private byte[] pcapHdr_buf;

    public Pcap() {
        // get data from network
    }

    public Pcap(String filepath) {
        reader = new Reader(filepath);
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
            case DLT_EN10MB:
                cDatalink = Ethernet.class;
                break;
            case DLT_PPP:
                cDatalink = PPP.class;
                break;
            case DLT_IEEE802_11:
                cDatalink = IEEE80211.class;
                break;
        }

        if (cDatalink == null) {
            throw new PcapException("unsupported datalink type");
        }

        Constructor constructor = null;
        try {
            constructor = cDatalink.getDeclaredConstructor();
        } catch (NoSuchMethodException e) {
            e.printStackTrace();
        }
        return constructor;
    }

    public static void main(String[] args) {
        TEST.timer.start();
        Pcap pcap = new Pcap(TEST.getDir() + "ipv4.pcap");
        pcap.unpack();
        TEST.timer.end("Unpack");

        TEST.timer.start();
        System.out.println("MAGIC: " + pcap.field(Pcap.MAGIC));
        System.out.println("V_MAJOR: " + pcap.field(Pcap.V_MAJOR));
        System.out.println("V_MINOR: " + pcap.field(Pcap.V_MINOR));
        System.out.println("THISZONE: " + pcap.field(Pcap.THISZONE));
        System.out.println("SIGFIGS: " + pcap.field(Pcap.SIGFIGS));
        System.out.println("SNAPLEN: " + pcap.field(Pcap.SNAPLEN));
        System.out.println("LINKTYPE: " + pcap.field(Pcap.LINKTYPE));
        TEST.timer.end("PRINT");
    }
}
