package com.jduan.pcap;

import java.util.Iterator;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * This class is used for testing Class ARP.
 *
 * @author  Jiaxu Duan
 * @since   5/12/18
 * @see     com.jduan.pcap.Protocol
 */
final class ARP_Test {
    private final static Timer timer = new Timer();
    private static Protocol arp;

    @BeforeAll
    static void start() {
        timer.start();
        Pcap pcap = new Pcap(AH_Test.class.getResource("/arp.pcap").getPath());
        pcap.unpack();

        Iterator<Protocol> iter = pcap.iterator();
        Protocol eth = iter.next();
        assertTrue(eth instanceof Ethernet);
        arp = eth.next();
        assertTrue(arp instanceof ARP);
        timer.end("AH_Test Unpack Time-consuming");
    }

    @AfterAll
    static void end() {
        /* no-op */
    }

    @Test
    @DisplayName("Test 'HTYPE' field")
    void HTYPE_test() {
        assertEquals(arp.field(ARP.HTYPE), "1");
    }

    @Test
    @DisplayName("Test 'PTYPE' field")
    void PTYPE_test() {
        assertEquals(arp.field(ARP.PTYPE), "0x0800");
    }

    @Test
    @DisplayName("Test 'HLEN' field")
    void HLEN_test() {
        assertEquals(arp.field(ARP.HLEN), "6");
    }

    @Test
    @DisplayName("Test 'PLEN' field")
    void PLEN_test() {
        assertEquals(arp.field(ARP.PLEN), "4");
    }

    @Test
    @DisplayName("Test 'OPERATION' field")
    void OPERATION_test() {
        assertEquals(arp.field(ARP.OPERATION), "1");
    }

    @Test
    @DisplayName("Test 'SHA' field")
    void SHA_test() {
        assertEquals(arp.field(ARP.SHA), "00:07:0d:af:f4:54");
    }

    @Test
    @DisplayName("Test 'SPA' field")
    void SPA_test() {
        assertEquals(arp.field(ARP.SPA), "24.166.172.1");
    }

    @Test
    @DisplayName("Test 'THA' field")
    void THA_test() {
        assertEquals(arp.field(ARP.THA), "00:00:00:00:00:00");
    }

    @Test
    @DisplayName("Test 'TPA' field")
    void TPA_test() {
        assertEquals(arp.field(ARP.TPA), "24.166.173.159");
    }
}
