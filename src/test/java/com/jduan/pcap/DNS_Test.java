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
final class DNS_Test {
    private final static Timer timer = new Timer();
    private static Protocol dns;

    @BeforeAll
    static void start() {
        timer.start();
        Pcap pcap = new Pcap(AH_Test.class.getResource("/dns.pcap").getPath());
        pcap.unpack();

        Iterator<Protocol> iter = pcap.iterator();
        Protocol eth = iter.next();
        assertTrue(eth instanceof Ethernet);
        Protocol ipv4 = eth.next();
        assertTrue(ipv4 instanceof IPv4);
        Protocol udp = ipv4.next();
        assertTrue(udp instanceof UDP);
        dns = udp.next();
        assertTrue(dns instanceof DNS);
        timer.end("DNS test case unpack time-consuming");
    }

    @AfterAll
    static void end() {
        /* no-op */
    }

    @Test
    @DisplayName("Test 'ID' field")
    void ID_test() {
        assertEquals(dns.field(DNS.ID), "0x0001");
    }

    @Test
    @DisplayName("Test 'QR' field")
    void QR_test() {
        assertEquals(dns.field(DNS.QR), "0");
    }

    @Test
    @DisplayName("Test 'OPCODE' field")
    void OPCODE_test() {
        assertEquals(dns.field(DNS.OPCODE), "0");
    }

    @Test
    @DisplayName("Test 'AA' field")
    void AA_test() {
        assertEquals(dns.field(DNS.AA), "0");
    }

    @Test
    @DisplayName("Test 'TC' field")
    void TC_test() {
        assertEquals(dns.field(DNS.TC), "0");
    }

    @Test
    @DisplayName("Test 'RD' field")
    void RD_test() {
        assertEquals(dns.field(DNS.RD), "1");
    }

    @Test
    @DisplayName("Test 'RA' field")
    void RA_test() {
        assertEquals(dns.field(DNS.RA), "0");
    }

    @Test
    @DisplayName("Test 'RCODE' field")
    void RCODE_test() {
        assertEquals(dns.field(DNS.RCODE), "0");
    }

    @Test
    @DisplayName("Test 'QDCOUNT' field")
    void QDCOUNT_test() {
        assertEquals(dns.field(DNS.QDCOUNT), "1");
    }

    @Test
    @DisplayName("Test 'ANCOUNT' field")
    void ANCOUNT_test() {
        assertEquals(dns.field(DNS.ANCOUNT), "0");
    }

    @Test
    @DisplayName("Test 'NSCOUNT' field")
    void NSCOUNT_test() {
        assertEquals(dns.field(DNS.NSCOUNT), "0");
    }

    @Test
    @DisplayName("Test 'ARCOUNT' field")
    void ARCOUNT_test() {
        assertEquals(dns.field(DNS.ARCOUNT), "0");
    }
}
