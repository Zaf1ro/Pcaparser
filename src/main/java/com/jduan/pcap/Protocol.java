package com.jduan.pcap;


/**
 * This abstract class provides uniform access to
 * the fields of the <tt>Protocol</tt>.
 *
 * @author  Jiaxu Duan
 * @since   5/12/18
 */
public abstract class Protocol implements IProtocol {
    byte[] data_buf = null;
    Protocol nextLayer = null;

    @Override
    public Protocol next() {
        return nextLayer;
    }

    @Override
    public void print() {
        System.out.println(text());
    }

    @Override
    public void printAll() {
        print();
        if (nextLayer != null)
            nextLayer.print();
        else
            System.out.println();
    }
}
