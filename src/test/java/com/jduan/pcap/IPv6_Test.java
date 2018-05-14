package com.jduan.pcap;

import java.util.Iterator;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 * This class is used for testing Class IPv6.
 *
 * @author  Jiaxu Duan
 * @since   5/12/18
 */
final class IPv6_Test {
    private final static Timer timer = new Timer();
    private static Protocol ipv6;

    @BeforeAll
    static void start() {
        timer.start();
        Pcap pcap = new Pcap(IPv6_Test.class.getResource("/ipv6.pcap").getPath());
        pcap.unpack();

        Iterator<Protocol> iter = pcap.iterator();
        Protocol eth = iter.next();
        assertTrue(eth instanceof Ethernet);
        ipv6 = eth.next();
        assertTrue(ipv6 instanceof IPv6);
        timer.end("IPv6 test case unpack time-consuming");
    }

    @AfterAll
    static void end() {
        /* no-op */
    }

    @Test
    @DisplayName("Test 'VERSION' field")
    void VERSION_test() {
        assertEquals(ipv6.field(IPv6.VERSION), "6");
    }

    @Test
    @DisplayName("Test 'TRAFFI_CLASS' field")
    void TRAFFI_CLASS_test() {
        assertEquals(ipv6.field(IPv6.TRAFFI_CLASS), "0xc0");
    }

    @Test
    @DisplayName("Test 'FLOW_LABEL' field")
    void FLOW_LABEL_test() {
        assertEquals(ipv6.field(IPv6.FLOW_LABEL), "0x00000");
    }

    @Test
    @DisplayName("Test 'PAYLOAD_LENGTH' field")
    void PAYLOAD_LENGTH_test() {
        assertEquals(ipv6.field(IPv6.PAYLOAD_LENGTH), "65");
    }

    @Test
    @DisplayName("Test 'NEXT_HEADER' field")
    void NEXT_HEADER_test() {
        assertEquals(ipv6.field(IPv6.NEXT_HEADER), "6");
    }

    @Test
    @DisplayName("Test 'HOP_LIMIT' field")
    void HOP_LIMIT_test() {
        assertEquals(ipv6.field(IPv6.HOP_LIMIT), "64");
    }

    @Test
    @DisplayName("Test 'SRC_ADDR' field")
    void SRC_ADDR_test() {
        assertEquals(ipv6.field(IPv6.SRC_ADDR), "2001:db8:0:0:0:0:0:1");
    }

    @Test
    @DisplayName("Test 'DST_ADDR' field")
    void DST_ADDR_test() {
        assertEquals(ipv6.field(IPv6.DST_ADDR), "2001:db8:0:0:0:0:0:2");
    }
}