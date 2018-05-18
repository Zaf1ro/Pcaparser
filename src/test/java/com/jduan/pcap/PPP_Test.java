package com.jduan.pcap;

import java.util.Iterator;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;


/**
 * This class is used for test Class PPP
 *
 * @author Jiaxu Duan
 * @since 5/18/18
 */
final class PPP_Test {
    private final static Timer timer = new Timer();
    private static Protocol ppp;

    @BeforeAll
    static void start() {
        timer.start();
        Pcap pcap = new Pcap(PPP_Test.class.getResource("/ppp.pcap").getPath());
        pcap.unpack();

        Iterator<Protocol> iter = pcap.iterator();
        ppp = iter.next();
        timer.end("PPP test case unpack time-consuming");
    }

    @AfterAll
    static void end() {
        /* no-op */
    }

    @Test
    @DisplayName("Test 'ADDR' field")
    void ADDR_test() {
        assertEquals(ppp.field(PPP.ADDR), "0xff");
    }

    @Test
    @DisplayName("Test 'CONTROL' field")
    void CONTROL_test() {
        assertEquals(ppp.field(PPP.CONTROL), "0x03");
    }

    @Test
    @DisplayName("Test 'PROTOCOL' field")
    void PROTOCOL_test() {
        assertEquals(ppp.field(PPP.PROTOCOL), "0x0021");
    }
}