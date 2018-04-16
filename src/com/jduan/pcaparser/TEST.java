package com.jduan.pcaparser;

import java.io.File;
import java.io.IOException;
import java.util.Calendar;
import java.util.Iterator;
import java.util.logging.*;


class Timer {
    private long start = 0;

    void start() {
        if(start > 0) {
            System.out.println("Warn - Please End the timer before starting!!!");
            return;
        }
        start = System.currentTimeMillis();
    }

    void end(String pre) {
        System.out.printf("%s: %s %s\n", pre, System.currentTimeMillis() - start, "millisec");
        start = 0;
    }
}


public class TEST {
    private final static Logger LOGGER = Logger.getLogger(TEST.class.getName());
    public final static Timer timer = new Timer();

    static String getDir() {
        String pcap_path = "";
        try {
            File dir = new File("examples");
            pcap_path = dir.getCanonicalPath() + File.separator;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return pcap_path;
    }

    private static void test_log(Pcap pcap) {
        Calendar cal = Calendar.getInstance();
        String current_time = Integer.toString(cal.get(Calendar.YEAR)) + "-"
                + Integer.toString(cal.get(Calendar.MONTH)) + "/"
                + Integer.toString(cal.get(Calendar.DATE)) + " "
                + Integer.toString(cal.get(Calendar.HOUR)) + ":"
                + Integer.toString(cal.get(Calendar.MINUTE)) + ":" +
                Integer.toString(cal.get(Calendar.SECOND));

        long s2 = System.currentTimeMillis();
        Iterator<Packet> iter = pcap.iterator();
        while(iter.hasNext()) {
            Packet p = iter.next();
//            LogRecord lr = new LogRecord(Level.INFO, "This is a text log.");
//            logger.log(lr);
            p.print();
        }


        try {
            FileHandler fileHandler = new FileHandler(getDir() + current_time + ".txt");
            SimpleFormatter sf = new SimpleFormatter();     /* format */
            fileHandler.setFormatter(sf);
            LOGGER.addHandler(fileHandler);
        } catch (IOException e) {
            e.printStackTrace();
        }

        long e2 = System.currentTimeMillis();
        System.out.printf("%s: %d sec\n", "UNPACK: ", e2 - s2);
    }

    private static void test_print(Pcap pcap) {
        long s2 = System.currentTimeMillis();
        Iterator<Packet> iter = pcap.iterator();
        while(iter.hasNext()) {
            Packet p = iter.next();
            p.print();
        }
        long e2 = System.currentTimeMillis();
        System.out.printf("%s: %d sec\n", "UNPACK: ", e2 - s2);
    }

    private static void test(String filename,
                             int type   /* 0: no print, no log
                                         * 1: print into console
                                         * 2: write into log
                                         */
    ) {
        long s1 = System.currentTimeMillis();
        Pcap pcap = new Pcap(getDir() + filename);
        pcap.unpack();
        long e1 = System.currentTimeMillis();
        System.out.printf("%s: %d sec\n", "UNPACK: ", e1 - s1);

        switch(type) {
            case 0:
                System.out.println("NO LOG: Spend no time");
                break;
            case 1:

                break;
            case 2:
                break;
        }
    }

    public static void main(String[] args){

    }
}
