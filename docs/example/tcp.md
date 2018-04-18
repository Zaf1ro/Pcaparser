# Print Ethernet Example
This example uses Pcaparser to read in a pcap file and print out each field of TCP in the first packet of pcap file
 
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
            Protocol tcp = ipv4.next();
            if (tcp instanceof TCP) {
                System.out.println("SPORT: " + tcp.field(TCP.SPORT));
                System.out.println("DPORT: " + tcp.field(TCP.DPORT));
                System.out.println("SEQ: " + tcp.field(TCP.SEQ));
                System.out.println("ACK: " + tcp.field(TCP.ACK));
                System.out.println("OFFSET : " + tcp.field(TCP.OFFSET));
                System.out.println("FLAGS " + tcp.field(TCP.FLAGS));
                System.out.println("WINDOW: " + tcp.field(TCP.WINDOW));
                System.out.println("CHECKSUM: " + tcp.field(TCP.CHECKSUM));
                System.out.println("URP: " + tcp.field(TCP.URP));
            }
        }
    }
}
```
 
#### Output
```text
SPORT: 2096
DPORT: 80
SEQ: 0x995fcf78
ACK: 0x00000000
OFFSET : 7
FLAGS 0x0002
WINDOW: 65535
CHECKSUM: 0xf98f
URP: 0
```
