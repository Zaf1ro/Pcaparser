package com.jduan.pcap;


import java.nio.ByteOrder;

public class Utils {
    private final static char[] HEXARRAY = "0123456789abcdef".toCharArray();
    private final static boolean ISBIGENDIAN = ByteOrder.nativeOrder().equals("BIG_ENDIAN");

    static String bytes2Hex(byte[] bytes, int ofst, int length) {
        char[] hexChars = new char[length * 2];
        for (int i = 0, j = 0; j < length; j++) {
            int v = bytes[ofst + j] & 0xFF;
            hexChars[i++] = HEXARRAY[v >>> 4];
            hexChars[i++] = HEXARRAY[v & 0x0F];
        }
        return String.format("0x%s", new String(hexChars));
    }

    static String bytes2MAC(byte[] bytes, int ofst) {
        return String.format("%02x:%02x:%02x:%02x:%02x:%02x",
                bytes[ofst] & 0xFF,
                bytes[ofst + 1] & 0xFF,
                bytes[ofst + 2] & 0xFF,
                bytes[ofst + 3] & 0xFF,
                bytes[ofst + 4] & 0xFF,
                bytes[ofst + 5] & 0xFF
        );
    }

    static String bytes2IPv4(byte[] bytes, int ofst) {
        return String.format("%d.%d.%d.%d",
                bytes[ofst] & 0xFF,
                bytes[ofst+1] & 0xFF,
                bytes[ofst+2] & 0xFF,
                bytes[ofst+3] & 0xFF
        );
    }

    static String bytes2IPv6(byte[] bytes, int ofst) {
        return String.format("%x:%x:%x:%x:%x:%x:%x:%x",
                bBytes2Short(bytes, ofst),
                bBytes2Short(bytes, ofst + 2),
                bBytes2Short(bytes, ofst + 4),
                bBytes2Short(bytes, ofst + 6),
                bBytes2Short(bytes, ofst + 8),
                bBytes2Short(bytes, ofst + 10),
                bBytes2Short(bytes, ofst + 12),
                bBytes2Short(bytes, ofst + 14)
        );
    }

    static short bBytes2Short(byte[] bytes, int ofst) {
        return (short) ((bytes[ofst] & 0xFF) << 8 | (bytes[ofst+1]) & 0xFF);
    }

    static short lBytes2Short(byte[] bytes, int ofst) {
        return (short) ((bytes[ofst+1] & 0xFF) << 8 | (bytes[ofst]) & 0xFF);
    }

    static int bBytes2Int(byte[] bytes, int ofst) {
        return (bytes[ofst] & 0xFF) << 24
            | (bytes[ofst+1] & 0xFF) << 16
            | (bytes[ofst+2] & 0xFF) << 8
            | (bytes[ofst+3] & 0xFF);
    }

    static int lBytes2Int(byte[] bytes, int ofst) {
        return (bytes[ofst+3] & 0xFF) << 24
            | (bytes[ofst+2] & 0xFF) << 16
            | (bytes[ofst+1] & 0xFF) << 8
            | (bytes[ofst] & 0xFF);
    }
}
