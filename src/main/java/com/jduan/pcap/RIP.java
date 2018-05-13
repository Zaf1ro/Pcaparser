package com.jduan.pcap;
import java.util.Iterator;

/* http://cs.baylor.edu/~donahoo/tools/hacknet/original/Rip/techni.htm */
public class RIP extends Protocol {
    public final static int COMMAND = 0;    /* 1, packet type */
    public final static int VERSION = 1;    /* 1, RIP version number */
    public final static int AFI = 2;        /* 2, when it is 2, it represents IP */
    public final static int IADDR = 3;      /* 4-8, the destination IP address */
    public final static int METRIC = 4;     /* 4, the hop count to its destination */

    private int start;
    private int RIP_LEN = 24;

    RIP(byte[] __buf, int __start) {
        assert (__buf != null);
        data_buf = __buf;
        start = __start;
        nextLayer = link();
    }

    private Protocol link() {
        return null;
    }

    public String field(int id) {
        assert (data_buf != null);
        switch (id) {
            case COMMAND:
                return Byte.toString(data_buf[start]);
            case VERSION:
                return Byte.toString(data_buf[start+1]);
            case AFI:
                return Short.toString(Utils.bBytes2Short(data_buf, start+4));
            case IADDR:
                return Utils.bytes2IPv4(data_buf, start+8);
            case METRIC:
                return Integer.toString(Utils.bBytes2Int(data_buf, start+20));
            default:
                return null;
        }
    }

    public String type() {
        return "RIP";
    }

    public String text() {
        return String.format("RIP:\t COMMAND:%s, VERSION:%s",
                field(RIP.COMMAND),
                field(RIP.VERSION)
        );
    }

    public static void main(String[] args) {
        Pcap pcap = new Pcap("rip.pcap");
        pcap.unpack();
        Iterator<Protocol> iter = pcap.iterator();
        iter.next();
        Protocol eth = iter.next();
        if (eth instanceof Ethernet) {
            Protocol ipv4 = eth.next();
            if (ipv4 instanceof IPv4) {
                Protocol udp = ipv4.next();
                if (udp instanceof UDP) {
                    Protocol rip = udp.next();
                    if(rip instanceof RIP) {
                        System.out.println("COMMAND: " + rip.field(RIP.COMMAND));
                        System.out.println("VERSION: " + rip.field(RIP.VERSION));
                        System.out.println("AFI: " + rip.field(RIP.AFI));
                        System.out.println("IADDR: " + rip.field(RIP.IADDR));
                        System.out.println("METRIC: " + rip.field(RIP.METRIC));
                    }
                }
            }
        }
    }
}
