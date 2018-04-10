package com.jduan.pcaparser;

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
    static PcapHdr pcapHdr;

    public Pcap() {
        // get data from network
    }

    public Pcap(String filepath) {
        reader = new Reader(filepath);
        packets = new ArrayList<>();
//        proto_map = new HashMap<>();
    }

    public void unpack() {
        pcapHdr = new PcapHdr();
        /* check datalink type */
        int linktype = pcapHdr.get_linktype();


        while (true) {
            Packet aPacket = new Packet();
            if (!reader.isRemaining())
                break;
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
}
