package com.jduan.pcaparser;


import java.util.Arrays;

public final class IPv4 implements Packet {
    public final static int VERSION = 0;
    public final static int IHL = 1;
    public final static int TOS = 2;
    public final static int ECN = 3;
    public final static int TOTAL_LENGTH = 4;
    public final static int IDENTIFICATION = 5;
    public final static int FLAGS = 6;
    public final static int FRAGMENT_OFFSET = 7;
    public final static int TTL = 8;
    public final static int PROTOCOL = 9;
    public final static int CHECKSUM = 10;
    public final static int SRC_IP = 11;
    public final static int DST_IP = 12;
    public final static int OPTIONS = 13;

    private final static int IP_LEN = 20;

    private byte[] data_buf;
    private int start;
    private Packet nextLayer;

    IPv4(byte[] __buf, int __start) {
        assert (__buf != null);
        data_buf = __buf;
        start = __start;
        link();
    }

    private void link() {
        int type = data_buf[start + 6];     // proto
        switch (type) {
//            case 0x01:        /* ICMP */
//                nextLayer = new ICMP(data_buf, start + IP_LEN);
//                break;
//            case 0x06:        /* TCP */
//                nextLayer = new TCP(data_buf, start + IP_LEN);
//                break;
//            case 0x11:        /* UDP */
//                nextLayer = new UDP(data_buf, start + IP_LEN);
//                break;
        }
    }

    public String field(int id) {
        assert(data_buf != null);

        switch (id) {
            case VERSION:
                return Integer.toString((data_buf[start] >>> 4) & 0x0F);
            case IHL:
                return Integer.toString(data_buf[start] & 0x0F);
            case TOS:
                return Integer.toString((data_buf[start+1] >>> 2) & 0xFF);
            case ECN:
                return Integer.toString(data_buf[start+1] & 0x03);
            case TOTAL_LENGTH:
                return Short.toString(Utils.byteArrayToShort(data_buf, 2));
            case IDENTIFICATION:
                return Short.toString(Utils.byteArrayToShort(data_buf, 4));
            case FLAGS:
                return Integer.toString((data_buf[start+6] >>> 5) & 0x03);
            case FRAGMENT_OFFSET:
                return Integer.toString(
                        (Utils.byteArrayToShort(data_buf, 6) >>> 3)
                );
            case TTL:
                return Byte.toString(data_buf[start+8]);
            case PROTOCOL:
                return Byte.toString(data_buf[start+9]);
            case CHECKSUM:
                return Short.toString(Utils.byteArrayToShort(data_buf, 10));
            case SRC_IP:
                return Utils.byteArrayToIP(data_buf, start+12);
            case DST_IP:
                return Utils.byteArrayToIP(data_buf, start+16);
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
            Utils.byteArrayToShort(data_buf, 2),
            Utils.byteArrayToShort(data_buf, 4),
            Utils.byteArrayToIP(data_buf, start+12),
            Utils.byteArrayToIP(data_buf, start+16)
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
