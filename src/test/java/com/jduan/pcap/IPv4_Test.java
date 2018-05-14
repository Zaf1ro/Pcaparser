package com.jduan.pcap;

import java.util.Iterator;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 * This class is used for testing Class IPv4.
 *
 * @author  Jiaxu Duan
 * @since   5/12/18
 */
final class IPv4_Test {
    private final static Timer timer = new Timer();
    private static Protocol ipv4;

    @BeforeAll
    static void start() {
        timer.start();
        Pcap pcap = new Pcap(IPv4_Test.class.getResource("/ipv4.pcap").getPath());
        pcap.unpack();

        Iterator<Protocol> iter = pcap.iterator();
        Protocol eth = iter.next();
        assertTrue(eth instanceof Ethernet);
        ipv4 = eth.next();
        assertTrue(ipv4 instanceof IPv4);
        timer.end("IPv4 test case unpack time-consuming");
    }

    @AfterAll
    static void end() {
        /* no-op */
    }

    @Test
    @DisplayName("Test 'VERSION' field")
    void VERSION_test() {
        assertEquals(ipv4.field(IPv4.VERSION), "4");
    }

    @Test
    @DisplayName("Test 'IHL' field")
    void IHL_test() {
        assertEquals(ipv4.field(IPv4.IHL), "5");
    }

    @Test
    @DisplayName("Test 'TOS' field")
    void TOS_test() {
        assertEquals(ipv4.field(IPv4.TOS), "0x00");
    }

    @Test
    @DisplayName("Test 'ECN' field")
    void ECN_test() {
        assertEquals(ipv4.field(IPv4.ECN), "0");
    }

    @Test
    @DisplayName("Test 'TOTAL_LENGTH' field")
    void TOTAL_LENGTH_test() {
        assertEquals(ipv4.field(IPv4.TOTAL_LENGTH), "996");
    }

    @Test
    @DisplayName("Test 'IDENTIFICATION' field")
    void IDENTIFICATION_test() {
        assertEquals(ipv4.field(IPv4.IDENTIFICATION), "0xb5d0");
    }

    @Test
    @DisplayName("Test 'FLAGS' field")
    void FLAGS_test() {
        assertEquals(ipv4.field(IPv4.FLAGS), "0x01");
    }

    @Test
    @DisplayName("Test 'FRAGMENT_OFFSET' field")
    void FRAGMENT_OFFSET_test() {
        assertEquals(ipv4.field(IPv4.FRAGMENT_OFFSET), "0");
    }

    @Test
    @DisplayName("Test 'TTL' field")
    void TTL_test() {
        assertEquals(ipv4.field(IPv4.TTL), "64");
    }

    @Test
    @DisplayName("Test 'PROTOCOL' field")
    void PROTOCOL_test() {
        assertEquals(ipv4.field(IPv4.PROTOCOL), "1");
    }

    @Test
    @DisplayName("Test 'CHECKSUM' field")
    void CHECKSUM_test() {
        assertEquals(ipv4.field(IPv4.CHECKSUM), "0x9b44");
    }

    @Test
    @DisplayName("Test 'SRC_ADDR' field")
    void SRC_ADDR_test() {
        assertEquals(ipv4.field(IPv4.SRC_ADDR), "2.1.1.2");
    }

    @Test
    @DisplayName("Test 'DST_ADDR' field")
    void DST_ADDR_test() {
        assertEquals(ipv4.field(IPv4.DST_ADDR), "2.1.1.1");
    }

    @Test
    @DisplayName("Test 'OPTIONS' field")
    void OPTIONS_test() {
        assertEquals(ipv4.field(IPv4.OPTIONS), "");
    }
}
