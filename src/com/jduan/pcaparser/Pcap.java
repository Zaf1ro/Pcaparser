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
    //    static Map<String, Packet> proto_map;
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
        Class Datalink = null;
        switch (linktype) {
            case 0x01:      /* DLT_EN10MB */
            case 0x03:      /* DLT_EN3MB */
                Datalink = Ethernet.class;
                break;
            case 0x0A:      /* DLT_PPP */
                break;
        }

        if(Datalink == null) {
            throw new PcapException("unsupported datalink type");
        }

        Constructor constructor = null;
        try {
            constructor = Datalink.getDeclaredConstructor();
        } catch (NoSuchMethodException e) {
            e.printStackTrace();
        }

        return constructor;
    }
}
