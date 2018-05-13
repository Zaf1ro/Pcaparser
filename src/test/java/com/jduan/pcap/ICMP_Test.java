package com.jduan.pcap;

import java.util.Iterator;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 * This class is used for testing Class ICMP.
 *
 * @author  Jiaxu Duan
 * @since   5/12/18
 */
final class ICMP_Test {
    private final static Timer timer = new Timer();
    private static Protocol icmp;

    @BeforeAll
    static void start() {
        timer.start();
        Pcap pcap = new Pcap(ICMP_Test.class.getResource("/icmp.pcap").getPath());
        pcap.unpack();

        Iterator<Protocol> iter = pcap.iterator();
        Protocol eth = iter.next();
        assertTrue(eth instanceof Ethernet);
        Protocol ipv4 = eth.next();
        assertTrue(ipv4 instanceof IPv4);
        icmp = ipv4.next();
        assertTrue(icmp instanceof ICMP);
        timer.end("ICMP test case unpack time-consuming");
    }

    @AfterAll
    static void end() {
        /* no-op */
    }

    @Test
    @DisplayName("Test 'TYPE' field")
    void TYPE_test() {
        assertEquals(icmp.field(ICMP.TYPE), "0");
    }

    @Test
    @DisplayName("Test 'CODE' field")
    void CODE_test() {
        assertEquals(icmp.field(ICMP.CODE), "0");
    }

    @Test
    @DisplayName("Test 'CHECKSUM' field")
    void CHECKSUM_test() {
        assertEquals(icmp.field(ICMP.CHECKSUM), "0x5571");
    }
}
