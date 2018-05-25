package com.jduan.pcap;

import java.util.Iterator;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * This class is used for test Class RTP
 *
 * @author Jiaxu Duan
 * @since 5/21/18
 */
final class RTP_Test {
    private final static Timer timer = new Timer();
    private static Protocol rtp;

    @BeforeAll
    static void start() {
        timer.start();
        Pcap pcap = new Pcap(RTP_Test.class.getResource("/rtp.pcap").getPath());
        pcap.unpack();

        Iterator<Protocol> iter = pcap.iterator();
        Protocol eth = iter.next();
        assertTrue(eth instanceof Ethernet);
        Protocol ipv4 = eth.next();
        assertTrue(ipv4 instanceof IPv4);
        Protocol udp = ipv4.next();
        assertTrue(udp instanceof UDP);
        rtp = udp.next();
        assertTrue(rtp instanceof RTP);
        timer.end("RTP test case unpack time-consuming");
    }

    @AfterAll
    static void end() {
        /* no-op */
    }

    @Test
    @DisplayName("Test 'VERSION' field")
    void VERSION_test() {
        assertEquals(rtp.field(RTP.VERSION), "2");
    }

    @Test
    @DisplayName("Test 'P' field")
    void P_test() {
        assertEquals(rtp.field(RTP.P), "0");
    }

    @Test
    @DisplayName("Test 'X' field")
    void X_test() {
        assertEquals(rtp.field(RTP.X), "0");
    }

    @Test
    @DisplayName("Test 'CC' field")
    void CC_test() {
        assertEquals(rtp.field(RTP.CC), "0000");
    }

    @Test
    @DisplayName("Test 'M' field")
    void M_test() {
        assertEquals(rtp.field(RTP.M), "0");
    }

    @Test
    @DisplayName("Test 'PT' field")
    void PT_test() {
        assertEquals(rtp.field(RTP.PT), "8");
    }

    @Test
    @DisplayName("Test 'SEQUENCE' field")
    void SEQUENCE_test() {
        assertEquals(rtp.field(RTP.SEQUENCE), "28590");
    }

    @Test
    @DisplayName("Test 'TIMESTAMP' field")
    void TIMESTAMP_test() {
        assertEquals(rtp.field(RTP.TIMESTAMP), "1240");
    }

    @Test
    @DisplayName("Test 'SSRC' field")
    void SSRC_test() {
        assertEquals(rtp.field(RTP.SSRC), "932629361");
    }
}
