package com.jduan.pcap;

import java.util.Iterator;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 * This class is used for testing Class LLC.
 *
 * @author  Jiaxu Duan
 * @since   5/12/18
 */
final class LLC_Test {
    private final static Timer timer = new Timer();
    private static Protocol llc;

    @BeforeAll
    static void start() {
        timer.start();
        Pcap pcap = new Pcap(LLC_Test.class.getResource("/ipv6.pcap").getPath());
        pcap.unpack();

        Iterator<Protocol> iter = pcap.iterator();
        Protocol eth = iter.next();
        assertTrue(eth instanceof Ethernet);
        llc = eth.next();
        assertTrue(llc instanceof LLC);
        timer.end("LLC test case unpack time-consuming");
    }

    @AfterAll
    static void end() {
        /* no-op */
    }

    @Test
    @DisplayName("Test 'DSAP' field")
    void DSAP_test() {
        assertEquals(llc.field(LLC.DSAP), "6");
    }

    @Test
    @DisplayName("Test 'SSAP' field")
    void SSAP_test() {
        assertEquals(llc.field(LLC.SSAP), "6");
    }

    @Test
    @DisplayName("Test 'CONTROL' field")
    void CONTROL_test() {
        assertEquals(llc.field(LLC.CONTROL), "6");
    }
}
