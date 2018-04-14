package com.jduan.pcaparser;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.ConcurrentModificationException;
import java.util.Iterator;
import java.util.NoSuchElementException;

/*
 * Enter of program
 */
public class Pcap {
    private final static int DLT_EN10MB = 0x0001;       /* IEEE 802.3 Ethernet */
    private final static int DLT_PPP = 0x0009;          /* Point-to-Point Protocol */
    private final static int DLT_IEEE802_11 = 0x0069;   /* IEEE 802.11 wireless LAN */

    static Reader reader;
    static ArrayList<Packet> packets;
    public PcapHdr pcapHdr;

    public Pcap() {
        // get data from network
    }

    public Pcap(String filepath) {
        reader = new Reader(filepath);
        packets = new ArrayList<>();
//        proto_map = new HashMap<>();
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
                Packet p = (Packet)constructor.newInstance();
                packets.add(p);
            } catch (InvocationTargetException | IllegalAccessException | InstantiationException e) {
                e.printStackTrace();
            }
        }
    }

//    public Packet find(String proto) {
//        return proto_map.getOrDefault(proto, null);
//    }

    public Iterator<Packet> iterator() {
        return new PacketItr();
    }

    public Iterator<Packet> iterator(int index) {
        return new PacketItr(index);
    }

    private class PacketItr implements Iterator<Packet> {
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

        public Packet next() {
            int i = cursor;
            if (i >= size)
                throw new NoSuchElementException();
            if (i >= packets.size())
                throw new ConcurrentModificationException();
            ++cursor;
            return packets.get(i);
        }

        public Packet previous() {
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
        pcapHdr = new PcapHdr();

        /* check datalink type */
        int linktype = pcapHdr.get_linktype();
        Class cDatalink = null;
        switch (linktype) {
            case DLT_EN10MB:      /* DLT_EN10MB */
                cDatalink = Ethernet.class;
                break;
            case DLT_PPP:      /* DLT_PPP */
                cDatalink = PPP.class;
                break;
            case DLT_IEEE802_11:
                cDatalink = IEEE80211.class;
                break;
        }

        if(cDatalink == null) {
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
}
