package com.jduan;
import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.assertEquals;


public class PcapTest {
    private final static Timer timer = new Timer();
    private static Pcap pcap;

    @BeforeAll
    static void start() {
        timer.start();
        pcap = new Pcap(PcapTest.class.getResource("/ipv4.pcap").getPath());
        pcap.unpack();
        timer.end("PcapTest Unpack Time-consuming");
    }

    @AfterAll
    static void end() {
        /* no-op */
    }

    @Test
    public void pkt_test() {
        assertEquals(pcap.field(Pcap.MAGIC), "0xd4c3b2a1");
    }

    @Test
    public void v_major_test() {
        assertEquals(pcap.field(Pcap.V_MAJOR), "2");
    }

    @Test
    public void v_minor_test() {
        assertEquals(pcap.field(Pcap.V_MINOR), "4");
    }

    @Test
    public void thiszone_test() {
        assertEquals(pcap.field(Pcap.THISZONE), "0");
    }

    @Test
    public void sigfigs_test() {
        assertEquals(pcap.field(Pcap.SIGFIGS), "0");
    }

    @Test
    public void snaplen_test() {
        assertEquals(pcap.field(Pcap.SNAPLEN), "2000");
    }

    @Test
    public void linktype_test() {
        assertEquals(pcap.field(Pcap.LINKTYPE), "1");
    }
}
