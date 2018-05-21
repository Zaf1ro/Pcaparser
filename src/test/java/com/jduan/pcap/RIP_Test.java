package com.jduan.pcap;

import java.util.Iterator;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 * This class is used for test Class RIP
 * 
 * @author Jiaxu Duan
 * @since 5/21/18
 */
public class RIP_Test {
    private final static Timer timer = new Timer();
    private static Protocol rip;

    @BeforeAll
    static void start() {
        timer.start();
        Pcap pcap = new Pcap(RIP_Test.class.getResource("/rip.pcap").getPath());
        pcap.unpack();

        Iterator<Protocol> iter = pcap.iterator();
        Protocol eth = iter.next();
        assertTrue(eth instanceof Ethernet);
        Protocol ipv4 = eth.next();
        assertTrue(ipv4 instanceof IPv4);
        Protocol udp = ipv4.next();
        assertTrue(udp instanceof UDP);
        rip = udp.next();
        assertTrue(rip instanceof RIP);
        timer.end("RIP test case unpack time-consuming");
    }

    @AfterAll
    static void end() {
        /* no-op */
    }

    @Test
    @DisplayName("Test 'COMMAND' field")
    void COMMAND_test() {
        assertEquals(rip.field(RIP.COMMAND), "2");
    }

    @Test
    @DisplayName("Test 'VERSION' field")
    void VERSION_test() {
        assertEquals(rip.field(RIP.VERSION), "1");
    }

    @Test
    @DisplayName("Test 'AFI' field")
    void AFI_test() {
        assertEquals(rip.field(RIP.AFI), "2");
    }

    @Test
    @DisplayName("Test 'IADDR' field")
    void IADDR_test() {
        assertEquals(rip.field(RIP.IADDR), "200.0.1.0");
    }

    @Test
    @DisplayName("Test 'METRIC' field")
    void METRIC_test() {
        assertEquals(rip.field(RIP.METRIC), "1");
    }
}
