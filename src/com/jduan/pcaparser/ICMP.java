package com.jduan.pcaparser;


/* https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Header */
public class ICMP implements Packet{
    public final static int TYPE = 0;            /* 1, ICMP type */
    public final static int CODE = 1;            /* 1, ICMP subtype */
    public final static int CHECKSUM = 2;        /* 2, Error checking data */
    public final static int REST_OF_HEADER = 3;  /* 4, contents vary based on type and code */

    private final static int ICMP_LEN = 20;

    private byte[] data_buf;
    private int start;
    private Packet nextLayer;

    ICMP(byte[] __buf, int __start) {
        assert (__buf != null);
        data_buf = __buf;
        start = __start;
        nextLayer = link();
    }

    private Packet link() {
        return null;
    }

    public String field(int id) {
        assert(data_buf != null);

        switch (id) {
            case TYPE:
                return Byte.toString(data_buf[start]);
            case CODE:
                return Byte.toString(data_buf[start+1]);
            case CHECKSUM:
                return String.format("%04x", Utils.bytes2Short(data_buf, start+2));
            case REST_OF_HEADER:
                return Utils.bytes2Hex(data_buf, start+4, start+8);
            default:
                return null;
        }
    }

    public String type() {
        return "ICMP";
    }

    public Packet next() {
        return nextLayer;
    }

    public String text() {
        return String.format("ICMP: len:%d, id:0x%04x, src:%s, dst:%s\n",
                Utils.bytes2Short(data_buf, start+2),
                Utils.bytes2Short(data_buf, start+4),
                Utils.bytes2IPv4(data_buf, start+12),
                Utils.bytes2IPv4(data_buf, start+16)
        );
    }

    public void print() {
        System.out.print(text());
    }

    public void printAll() {
        print();
        if(nextLayer != null)
            nextLayer.print();
        else
            System.out.println();
    }
}
