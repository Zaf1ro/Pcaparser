package com.jduan.pcap;

import java.util.Iterator;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 * This class is used for testing Class Ethernet.
 *
 * @author  Jiaxu Duan
 * @since   5/12/18
 */
final class Ethernet_Test {
    private final static Timer timer = new Timer();
    private static Protocol eth;

    @BeforeAll
    static void start() {
        timer.start();
        Pcap pcap = new Pcap(Ethernet_Test.class.getResource("/eth.pcap").getPath());
        pcap.unpack();

        Iterator<Protocol> iter = pcap.iterator();
        eth = iter.next();
        assertTrue(eth instanceof Ethernet);
        timer.end("Ethernet test case unpack time-consuming");
    }

    @AfterAll
    static void end() {
        /* no-op */
    }

    @Test
    @DisplayName("Test 'DHOST' field")
    void DHOST_test() {
        assertEquals(eth.field(Ethernet.DHOST), "00:26:62:2f:47:87");
    }

    @Test
    @DisplayName("Test 'SHOST' field")
    void SHOST_test() {
        assertEquals(eth.field(Ethernet.SHOST), "00:1d:60:b3:01:84");
    }

    @Test
    @DisplayName("Test 'ETH_TYPE' field")
    void ETH_TYPE_test() {
        assertEquals(eth.field(Ethernet.ETH_TYPE), "0x0800");
    }
}
