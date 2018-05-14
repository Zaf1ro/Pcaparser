package com.jduan.pcap;

import java.util.Iterator;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 * This class is used for testing Class IEEE 802.3.
 *
 * @author Jiaxu Duan
 * @since 5/13/18
 */
final class IEEE8023_Test {
    private final static Timer timer = new Timer();
    private static Protocol eth;

    @BeforeAll
    static void start() {
        timer.start();
        Pcap pcap = new Pcap(EthernetII_Test.class.getResource("/llc.pcap").getPath());
        pcap.unpack();

        Iterator<Protocol> iter = pcap.iterator();
        eth = iter.next();
        assertTrue(eth instanceof Ethernet);
        timer.end("IEEE 802.3 test case unpack time-consuming");
    }

    @AfterAll
    static void end() {
        /* no-op */
    }

    @Test
    @DisplayName("Test 'DHOST' field")
    void DHOST_test() {
        assertEquals(eth.field(IEEE8023.DHOST), "01:00:0c:cc:cc:cc");
    }

    @Test
    @DisplayName("Test 'SHOST' field")
    void SHOST_test() {
        assertEquals(eth.field(IEEE8023.SHOST), "c4:02:32:6b:00:00");
    }

    @Test
    @DisplayName("Test 'LENGTH' field")
    void ETH_TYPE_test() {
        assertEquals(eth.field(IEEE8023.LENGTH), "340");
    }
}
