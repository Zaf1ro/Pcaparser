# Print Ethernet Example
This example uses Pcaparser to read in a pcap file and print out each field of IPv4 in the first packet of pcap file
 
#### Code
```java
import com.jduan.pcaparser.*;

public static void main(String[] args) {
    Pcap pcap = new Pcap("sample.pcap");
    pcap.unpack();

    Iterator<Protocol> iter = pcap.iterator();
    Protocol eth = iter.next();
    if (eth instanceof Ethernet) {
        Protocol ipv4 = eth.next();
        if (ipv4 instanceof IPv4) {
            System.out.println("VERSION: " + ipv4.field(IPv4.VERSION));
            System.out.println("IHL: " + ipv4.field(IPv4.IHL));
            System.out.println("TOS: " + ipv4.field(IPv4.TOS));
            System.out.println("ECN: " + ipv4.field(IPv4.ECN));
            System.out.println("TOTAL LENGTH: " + ipv4.field(IPv4.TOTAL_LENGTH));
            System.out.println("IDENTIFICATION: " + ipv4.field(IPv4.IDENTIFICATION));
            System.out.println("FLAGS: " + ipv4.field(IPv4.FLAGS));
            System.out.println("FRAGMENT OFFSET: " + ipv4.field(IPv4.FRAGMENT_OFFSET));
            System.out.println("TTL: " + ipv4.field(IPv4.TTL));
            System.out.println("PROTOCOL: " + ipv4.field(IPv4.PROTOCOL));
            System.out.println("CHECKSUM: " + ipv4.field(IPv4.CHECKSUM));
            System.out.println("SRC ADDR: " + ipv4.field(IPv4.SRC_ADDR));
            System.out.println("DST ADDR: " + ipv4.field(IPv4.DST_ADDR));
            System.out.println("OPTIONS: " + ipv4.field(IPv4.OPTIONS));
        }
    }
}
```
 
#### Output
```text
VERSION: 4
IHL: 5
TOS: 0x00
ECN: 0
TOTAL LENGTH: 996
IDENTIFICATION: 0xb5d0
FLAGS: 0x01
FRAGMENT OFFSET: 0
TTL: 64
PROTOCOL: 1
CHECKSUM: 0x9b44
SRC ADDR: 2.1.1.2
DST ADDR: 2.1.1.1
OPTIONS: 
```
