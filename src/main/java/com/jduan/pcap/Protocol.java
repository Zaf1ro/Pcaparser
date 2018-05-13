package com.jduan.pcap;


public abstract class Protocol implements IProtocol {
    byte[] data_buf = null;
    Protocol nextLayer = null;

    public Protocol next() {
        return nextLayer;
    }

    public void print() {
        System.out.println(text());
    }

    public void printAll() {
        print();
        if (nextLayer != null)
            nextLayer.print();
        else
            System.out.println();
    }
}