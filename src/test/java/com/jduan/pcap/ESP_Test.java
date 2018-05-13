package com.jduan.pcap;

import java.util.Iterator;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 * This class is used for testing Class DNS.
 *
 * @author  Jiaxu Duan
 * @since   5/12/18
 */
class ESP_Test {
    private final static Timer timer = new Timer();
    private static Protocol esp;

    @BeforeAll
    static void start() {
        timer.start();
        Pcap pcap = new Pcap(ESP_Test.class.getResource("/ipsec.pcap").getPath());
        pcap.unpack();

        Iterator<Protocol> iter = pcap.iterator();
        Protocol eth = iter.next();
        assertTrue(eth instanceof Ethernet);
        Protocol ipv4 = eth.next();
        assertTrue(ipv4 instanceof IPv4);
        esp = ipv4.next();
        assertTrue(esp instanceof ESP);
        timer.end("AH test case unpack time-consuming");
    }

    @AfterAll
    static void end() {
        /* no-op */
    }

    @Test
    @DisplayName("Test 'SPI' field")
    void SPI_test() {
        assertEquals(esp.field(ESP.SPI), "0x0000006e");
    }

    @Test
    @DisplayName("Test 'SEQUENCE' field")
    void SEQUENCE_test() {
        assertEquals(esp.field(ESP.SEQUENCE), "19");
    }
}
