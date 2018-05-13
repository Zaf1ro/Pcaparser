package com.jduan.pcap;

import java.util.Iterator;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 * This class is used for testing Class ICMP6.
 *
 * @author  Jiaxu Duan
 * @since   5/12/18
 */
final class IEEE80211_Test {
    private final static Timer timer = new Timer();
    private static Protocol ieee802_11;

    @BeforeAll
    static void start() {
        timer.start();
        Pcap pcap = new Pcap(IEEE80211_Test.class.getResource("/ieee802_11.pcap").getPath());
        pcap.unpack();

        Iterator<Protocol> iter = pcap.iterator();
        ieee802_11 = iter.next();
        assertTrue(ieee802_11 instanceof IEEE80211);
        timer.end("IEEE802.11 test case unpack time-consuming");
    }

    @AfterAll
    static void end() {
        /* no-op */
    }

    @Test
    @DisplayName("Test 'FRAME_CONTROL' field")
    void FRAME_CONTROL_test() {
        assertEquals(ieee802_11.field(IEEE80211.FRAME_CONTROL), "0x8000");
    }

    @Test
    @DisplayName("Test 'DURATION' field")
    void DURATION_test() {
        assertEquals(ieee802_11.field(IEEE80211.DURATION), "0");
    }

    @Test
    @DisplayName("Test 'ADDR1' field")
    void ADDR1_test() {
        assertEquals(ieee802_11.field(IEEE80211.ADDR1), "ff:ff:ff:ff:ff:ff");
    }

    @Test
    @DisplayName("Test 'ADDR2' field")
    void ADDR2_test() {
        assertEquals(ieee802_11.field(IEEE80211.ADDR2), "00:01:e3:41:bd:6e");
    }

    @Test
    @DisplayName("Test 'ADDR3' field")
    void ADDR3_test() {
        assertEquals(ieee802_11.field(IEEE80211.ADDR3), "00:01:e3:41:bd:6e");
    }

    @Test
    @DisplayName("Test 'SEQUENCE' field")
    void SEQUENCE_test() {
        assertEquals(ieee802_11.field(IEEE80211.SEQUENCE), "0x10f0");
    }
}
