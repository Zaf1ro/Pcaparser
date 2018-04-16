package com.jduan.pcaparser;


public class Utils {
    private final static char[] HexArray = "0123456789ABCDEF".toCharArray();

    static int bytes2Int(byte[] bytes, int ofst) {
        return bytes[ofst+3] << 24
                | (bytes[ofst+2] & 0xFF) << 16
                | (bytes[ofst+1] & 0xFF) << 8
                | (bytes[ofst] & 0xFF);
    }

    static short bytes2Short(byte[] bytes, int ofst) {
        return (short) ((bytes[ofst] & 0xFF) << 8 | (bytes[ofst + 1] & 0xFF));
    }

    static String bytes2Hex(byte[] bytes, int ofst, int length) {
        char[] hexChars = new char[length * 2];
        for (int i = 0, j = length-1; j >= 0; j--) {
            int v = bytes[ofst+j] & 0xFF;
            hexChars[i++] = HexArray[v >>> 4];
            hexChars[i++] = HexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    static String bytes2MAC(byte[] bytes, int ofst) {
        return String.format("%02x:%02x:%02x:%02x:%02x:%02x",
                bytes[ofst] & 0xFF,
                bytes[ofst+1] & 0xFF,
                bytes[ofst+2] & 0xFF,
                bytes[ofst+3] & 0xFF,
                bytes[ofst+4] & 0xFF,
                bytes[ofst+5] & 0xFF
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
                bytes2Short(bytes, ofst),
                bytes2Short(bytes, ofst+2),
                bytes2Short(bytes, ofst+4),
                bytes2Short(bytes, ofst+6),
                bytes2Short(bytes, ofst+8),
                bytes2Short(bytes, ofst+10),
                bytes2Short(bytes, ofst+12),
                bytes2Short(bytes, ofst+14)
        );
    }
}
