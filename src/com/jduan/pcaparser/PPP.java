package com.jduan.pcaparser;

public class PPP extends PktHdr {
    public final static int ADDR = 0;       /* 1, standard broadcast address */
    public final static int CONTROL = 1;    /* 1, unnumbered data */
    public final static int PROTOCOL = 2;   /* 2, PPP ID of embedded data */

    private final static int PPP_LEN = 4;

    private byte[] data_buf;
    private Packet nextLayer;

    PPP() {
        super();
        data_buf = new byte[getDataLen()];
        Pcap.reader.fill(data_buf);
        nextLayer = link();
    }

    private Packet link() {
        /* get the layer 2 protocol */
        int type = Utils.bytes2Short(data_buf, 2) & 0xFFFF;
        switch (type) {
            default:
                return null;
        }
    }

    public String field(int id) {
        switch (id) {
            case ADDR:
                return String.format("%x", data_buf[0]);
            case CONTROL:
                return String.format("%x", data_buf[1]);
            case PROTOCOL:
                return String.format("%x", Utils.bytes2Short(data_buf, 2));
            default:
                return null;
        }
    }

    public String type() {
        return "PPP";
    }

    public Packet next() {
        return nextLayer;
    }

    public String text() {
        return String.format("PPP: addr:%x, control:%x, proto:%x\n",
                data_buf[0],
                data_buf[1],
                Utils.bytes2Short(data_buf, 2)
        );
    }

    public void print() {
        System.out.print(text());
    }

    public void printAll() {
        print();
        if(nextLayer != null)
            nextLayer.printAll();
        else
            System.out.println();
    }
}
