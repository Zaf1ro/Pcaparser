package com.jduan.pcap;

import java.util.Iterator;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 * This class is used for testing Class OSPF.
 *
 * @author  Jiaxu Duan
 * @since   5/12/18
 */
final class OSPF_Test {
    private final static Timer timer = new Timer();
    private static Protocol ospf;

    @BeforeAll
    static void start() {
        timer.start();
        Pcap pcap = new Pcap(OSPF_Test.class.getResource("/ospf.pcap").getPath());
        pcap.unpack();

        Iterator<Protocol> iter = pcap.iterator();
        Protocol eth = iter.next();
        assertTrue(eth instanceof Ethernet);
        Protocol ipv4 = eth.next();
        assertTrue(ipv4 instanceof IPv4);
        ospf = ipv4.next();
        assertTrue(ospf instanceof OSPF);
        timer.end("OSPF test case unpack time-consuming");
    }

    @AfterAll
    static void end() {
        /* no-op */
    }

    @Test
    @DisplayName("Test 'VERSION' field")
    void VERSION_test() {
        assertEquals(ospf.field(OSPF.VERSION), "2");
    }

    @Test
    @DisplayName("Test 'TYPE' field")
    void TYPE_test() {
        assertEquals(ospf.field(OSPF.TYPE), "1");
    }

    @Test
    @DisplayName("Test 'PACKET_LENGTH' field")
    void PACKET_LENGTH_test() {
        assertEquals(ospf.field(OSPF.PACKET_LENGTH), "44");
    }

    @Test
    @DisplayName("Test 'ROUTER_ID' field")
    void ROUTER_ID_test() {
        assertEquals(ospf.field(OSPF.ROUTER_ID), "192.168.170.8");
    }

    @Test
    @DisplayName("Test 'AREA_ID' field")
    void AREA_ID_test() {
        assertEquals(ospf.field(OSPF.AREA_ID), "0.0.0.1");
    }

    @Test
    @DisplayName("Test 'CHECKSUM' field")
    void CHECKSUM_test() {
        assertEquals(ospf.field(OSPF.CHECKSUM), "0x273b");
    }

    @Test
    @DisplayName("Test 'AUTYPE' field")
    void AUTYPE_test() {
        assertEquals(ospf.field(OSPF.AUTYPE), "0");
    }

    @Test
    @DisplayName("Test 'AUTHENTICATION' field")
    void AUTHENTICATION_test() {
        assertEquals(ospf.field(OSPF.AUTHENTICATION), "0x0000000000000000");
    }
}
