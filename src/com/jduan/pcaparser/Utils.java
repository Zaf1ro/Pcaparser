package com.jduan.pcaparser;

import java.util.HashMap;
import java.util.Map;


public class Utils {
    private final static char[] HexArray = "0123456789ABCDEF".toCharArray();

    static int byteArrayToInt(byte[] bytes, int ofst) {
        return bytes[ofst+3] << 24 | (bytes[ofst+2] & 0xFF) << 16 |
                (bytes[ofst+1] & 0xFF) << 8 | (bytes[ofst] & 0xFF);
    }

    static short byteArrayToShort(byte[] bytes, int ofst) {
        return (short) ((bytes[ofst] & 0xFF) << 8 | (bytes[ofst + 1] & 0xFF));
    }

    static String byteArrayToHex(byte[] bytes, int ofst, int length) {
        char[] hexChars = new char[length * 2];
        for (int i = 0, j = length-1; j >= 0; j--) {
            int v = bytes[ofst+j] & 0xFF;
            hexChars[i++] = HexArray[v >>> 4];
            hexChars[i++] = HexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    static String byteArrayToMAC(byte[] bytes, int ofst) {
        return String.format("%02x", bytes[ofst] & 0xFF) + ":" +
                String.format("%02x", bytes[ofst+1] & 0xFF) + ":" +
                String.format("%02x", bytes[ofst+2] & 0xFF) + ":" +
                String.format("%02x", bytes[ofst+3] & 0xFF) + ":" +
                String.format("%02x", bytes[ofst+4] & 0xFF) + ":" +
                String.format("%02x", bytes[ofst+5] & 0xFF);
    }

    static String byteArrayToIP(byte[] bytes, int ofst) {
        return Integer.toString(bytes[ofst] & 0xFF) + "."
                + Integer.toString(bytes[ofst+1] & 0xFF) + "."
                + Integer.toString(bytes[ofst+2] & 0xFF) + "."
                + Integer.toString(bytes[ofst+3] & 0xFF);
    }

    public static void main(String[] args) {
//        byte[] test = {111,121,122,127,5,6,7,8,-1,-2,-3,-4};
//        System.out.println(byteArrayToInt(test, 4));

        int[] a = {1,2,3,3,3,4,5,6,6};
        singleNumber(a);
    }

    public static void singleNumber(int[] nums) {
        for(int i = 0, j = 1; j < nums.length; j++) {
            if(nums[i] < nums[j]) {
                nums[++i] = nums[j];
            }
        }
        int a = 1;
    }
}
