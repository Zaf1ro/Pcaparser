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
final class ICMP6_Test {
    private final static Timer timer = new Timer();
    private static Protocol icmp6;

    @BeforeAll
    static void start() {
        timer.start();
        Pcap pcap = new Pcap(ICMP6_Test.class.getResource("/icmp6.pcap").getPath());
        pcap.unpack();

        Iterator<Protocol> iter = pcap.iterator();
        Protocol eth = iter.next();
        assertTrue(eth instanceof Ethernet);
        Protocol ipv4 = eth.next();
        assertTrue(ipv4 instanceof IPv4);
        Protocol ipv6 = ipv4.next();
        assertTrue(ipv6 instanceof IPv6);
        icmp6 = ipv6.next();
        assertTrue(icmp6 instanceof ICMP6);
        timer.end("ICMP test case unpack time-consuming");
    }

    @AfterAll
    static void end() {
        /* no-op */
    }

    @Test
    @DisplayName("Test 'TYPE' field")
    void TYPE_test() {
        assertEquals(icmp6.field(ICMP6.TYPE), "134");
    }

    @Test
    @DisplayName("Test 'CODE' field")
    void CODE_test() {
        assertEquals(icmp6.field(ICMP6.CODE), "0");
    }

    @Test
    @DisplayName("Test 'CHECKSUM' field")
    void CHECKSUM_test() {
        assertEquals(icmp6.field(ICMP6.CHECKSUM), "0x07ad");
    }
}