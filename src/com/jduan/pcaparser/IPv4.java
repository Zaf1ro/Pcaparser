package com.jduan.pcaparser;


import java.util.Arrays;

public final class IPv4 implements Packet {
    public final static int VERSION = 0;            /* 4b, version */
    public final static int IHL = 1;                /* 4b, internet Header Length */
    public final static int TOS = 2;                /* 6b, type of service */
    public final static int ECN = 3;                /* 2b, explicit Congestion Notification */
    public final static int TOTAL_LENGTH = 4;       /* 2, entire size including header and data */
    public final static int IDENTIFICATION = 5;     /* 2, identify the group of fragment */
    public final static int FLAGS = 6;              /* 3b, control fragment */
    public final static int FRAGMENT_OFFSET = 7;    /* 13b, offset of a particular fragment */
    public final static int TTL = 8;                /* 1, datagram's lifetime */
    public final static int PROTOCOL = 9;           /* 1, protocol number */
    public final static int CHECKSUM = 10;          /* 2, error-checking */
    public final static int SRC_ADDR = 11;            /* 4, ICMP address of sender */
    public final static int DST_ADDR = 12;            /* 4, ICMP address of the receiver */
    public final static int OPTIONS = 13;           /* 20, options field */

    private final static int IPv4_LEN = 20;

    private byte[] data_buf;
    private int start;
    private Packet nextLayer;

    IPv4(byte[] __buf, int __start) {
        assert (__buf != null);
        data_buf = __buf;
        start = __start;
        nextLayer = link();
    }

    private Packet link() {
        int type = data_buf[start+9];     // proto
        switch (type) {
            case 0x01:        /* ICMP */
                return new ICMP(data_buf, start + IPv4_LEN);
//            case 0x06:        /* TCP */
//                nextLayer = new TCP(data_buf, start + IP_LEN);
//                break;
//            case 0x11:        /* UDP */
//                nextLayer = new UDP(data_buf, start + IP_LEN);
//                break;
            default:
                return null;
        }
    }

    public String field(int id) {
        assert(data_buf != null);

        switch (id) {
            case VERSION:
                return Integer.toString(data_buf[start] >>> 4);
            case IHL:
                return Integer.toString(data_buf[start] & 0x0F);
            case TOS:
                return Integer.toString(data_buf[start+1] >>> 2);
            case ECN:
                return Integer.toString(data_buf[start+1] & 0x03);
            case TOTAL_LENGTH:
                return Short.toString(Utils.bytes2Short(data_buf, start+2));
            case IDENTIFICATION:
                return String.format("%04x", Utils.bytes2Short(data_buf, start+4));
            case FLAGS:
                return String.format("%02x", data_buf[start+6] >>> 5);
            case FRAGMENT_OFFSET:
                return Integer.toString(
                        Utils.bytes2Short(data_buf, start+6) & 0x1FFF
                );
            case TTL:
                return Byte.toString(data_buf[start+8]);
            case PROTOCOL:
                return Byte.toString(data_buf[start+9]);
            case CHECKSUM:
                return String.format("%04x", Utils.bytes2Short(data_buf, start+10));
            case SRC_ADDR:
                return Utils.bytes2IPv4(data_buf, start+12);
            case DST_ADDR:
                return Utils.bytes2IPv4(data_buf, start+16);
            case OPTIONS:
                return (data_buf[start] & 0x0F) > 5 ?
                    new String(Arrays.copyOfRange(data_buf, start+20, start+36)) : null;
            default:
                return null;
        }
    }

    public String type() {
        return "IPv4";
    }

    public Packet next() {
        return nextLayer;
    }
    
    public String text() {
        return String.format("IPv4: len:%d, id:0x%04x, src:%s, dst:%s\n",
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
