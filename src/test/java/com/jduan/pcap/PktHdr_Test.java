package com.jduan.pcap;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;


/**
 * This class is used for testing Class PktHdr.
 *
 * @author  Jiaxu Duan
 * @since   5/12/18
 */
final class Pcap_Test {
    private final static Timer timer = new Timer();
    private static Pcap pcap;

    @BeforeAll
    static void start() {
        timer.start();
        pcap = new Pcap(Pcap_Test.class.getResource("/ipv4.pcap").getPath());
        assertNotNull(pcap);
        pcap.unpack();
        timer.end("PktHdr test case unpack time-consuming");
    }

    @AfterAll
    static void end() {
        /* no-op */
    }

    @Test
    void pkt_test() {
        assertEquals(pcap.field(Pcap.MAGIC), "0xd4c3b2a1");
    }

    @Test
    void v_major_test() {
        assertEquals(pcap.field(Pcap.V_MAJOR), "2");
    }

    @Test
    void v_minor_test() {
        assertEquals(pcap.field(Pcap.V_MINOR), "4");
    }

    @Test
    void thiszone_test() {
        assertEquals(pcap.field(Pcap.THISZONE), "0");
    }

    @Test
    void sigfigs_test() {
        assertEquals(pcap.field(Pcap.SIGFIGS), "0");
    }

    @Test
    void snaplen_test() {
        assertEquals(pcap.field(Pcap.SNAPLEN), "2000");
    }

    @Test
    void linktype_test() {
        assertEquals(pcap.field(Pcap.LINKTYPE), "1");
    }
}
