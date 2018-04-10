package edu.jduan8.pcaparser;

import java.util.HashMap;
import java.util.Map;


public class Utils {
    final static Map<Integer, Class> isLinktype = new HashMap<Integer, Class>(){{
        put(2, Ethernet.class);     /* DLT_EN10MB */
        put(3, Ethernet.class);     /* DLT_EN3MB */
    }};

    static int byteArrayToInt(byte[] bytes, int ofst) {
        return bytes[ofst] << 24 | (bytes[ofst+1] & 0xFF) << 16 |
                (bytes[ofst+2] & 0xFF) << 8 | (bytes[ofst+3] & 0xFF);
    }

    static short byteArrayToShort(byte[] bytes, int ofst) {
        return (short)((bytes[ofst] & 0xFF) << 8 | (bytes[ofst+1] & 0xFF));
    }

    public static void main(String[] args) {
        byte[] test1 = {1,2,3,4};
        System.out.println(byteArrayToInt(test1, 0));
    }
}
