package com.jduan.pcap;

import java.util.Iterator;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;


/**
 * Test case for Class AH
 *
 * @author  Jiaxu Duan
 * @since   5/12/18
 * @see     com.jduan.pcap.Protocol
 */
final public class AH_Test {
    private final static Timer timer = new Timer();
    private static Protocol ah;

    @BeforeAll
    static void start() {
        timer.start();
        Pcap pcap = new Pcap(AH_Test.class.getResource("/ah.pcap").getPath());
        pcap.unpack();

        Iterator<Protocol> iter = pcap.iterator();
        Protocol eth = iter.next();
        assertTrue(eth instanceof Ethernet);
        Protocol ipv4 = eth.next();
        assertTrue(ipv4 instanceof IPv4);
        ah = ipv4.next();
        assertTrue(ah instanceof AH);
        timer.end("AH_Test Unpack Time-consuming");
    }

    @AfterAll
    static void end() {
        /* no-op */
    }

    @Test
    @DisplayName("Test 'next' field")
    void next_test() {
        assertEquals(ah.field(AH.NEXT), "50");
    }

    @Test
    @DisplayName("Test 'length' field")
    void length_test() {
        assertEquals(ah.field(AH.LENGTH), "4");
    }

    @Test
    @DisplayName("Test 'spi' field")
    void spi_test() {
        assertEquals(ah.field(AH.SPI), "0x8179b705");
    }

    @Test
    @DisplayName("Test 'sequence' field")
    void sequence_test() {
        assertEquals(ah.field(AH.SEQUENCE), "0x00000001");
    }

    @Test
    @DisplayName("Test 'icv' field")
    void icv_test() {
        assertEquals(ah.field(AH.ICV), "0x27cfc0a5e43d69b3728ec5b0");
    }
}
