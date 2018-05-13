package com.jduan.pcap;

import java.util.Iterator;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 * This class is used for testing Class DHCP.
 *
 * @author  Jiaxu Duan
 * @since   5/12/18
 */
class DHCP_Test {
    private final static Timer timer = new Timer();
    private static Protocol dhcp;

    @BeforeAll
    static void start() {
        timer.start();
        Pcap pcap = new Pcap(AH_Test.class.getResource("/dhcp.pcap").getPath());
        pcap.unpack();

        Iterator<Protocol> iter = pcap.iterator();
        Protocol eth = iter.next();
        assertTrue(eth instanceof Ethernet);
        Protocol ipv4 = eth.next();
        assertTrue(ipv4 instanceof IPv4);
        Protocol udp = ipv4.next();
        assertTrue(udp instanceof UDP);
        dhcp = udp.next();
        assertTrue(dhcp instanceof DHCP);
        timer.end("AH_Test Unpack Time-consuming");
    }

    @AfterAll
    static void end() {
        /* no-op */
    }

    @Test
    @DisplayName("Test 'OP' field")
    void OP_test() {
        assertEquals(dhcp.field(DHCP.OP), "1");
    }

    @Test
    @DisplayName("Test 'HTYPE' field")
    void HTYPE_test() {
        assertEquals(dhcp.field(DHCP.HTYPE), "0x01");
    }

    @Test
    @DisplayName("Test 'HLEN' field")
    void HLEN_test() {
        assertEquals(dhcp.field(DHCP.HLEN), "6");
    }

    @Test
    @DisplayName("Test 'HOPS' field")
    void HOPS_test() {
        assertEquals(dhcp.field(DHCP.HOPS), "0");
    }

    @Test
    @DisplayName("Test 'XID' field")
    void XID_test() {
        assertEquals(dhcp.field(DHCP.XID), "0x00003d1d");
    }

    @Test
    @DisplayName("Test 'SECS' field")
    void SECS_test() {
        assertEquals(dhcp.field(DHCP.SECS), "0");
    }

    @Test
    @DisplayName("Test 'FLAGS' field")
    void FLAGS_test() {
        assertEquals(dhcp.field(DHCP.FLAGS), "0x0000");
    }

    @Test
    @DisplayName("Test 'CIADDR' field")
    void CIADDR_test() {
        assertEquals(dhcp.field(DHCP.CIADDR), "0.0.0.0");
    }

    @Test
    @DisplayName("Test 'YIADDR' field")
    void YIADDR_test() {
        assertEquals(dhcp.field(DHCP.YIADDR), "0.0.0.0");
    }

    @Test
    @DisplayName("Test 'SIADDR' field")
    void SIADDR_test() {
        assertEquals(dhcp.field(DHCP.SIADDR), "0.0.0.0");
    }

    @Test
    @DisplayName("Test 'GIADDR' field")
    void GIADDR_test() {
        assertEquals(dhcp.field(DHCP.GIADDR), "0.0.0.0");
    }

    @Test
    @DisplayName("Test 'CHADDR' field")
    void CHADDR_test() {
        assertEquals(dhcp.field(DHCP.CHADDR), "00:0b:82:01:fc:42");
    }
}
