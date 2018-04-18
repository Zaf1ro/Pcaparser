# Print Ethernet Example
This example uses Pcaparser to read in a pcap file and print out each field of Ethernet in the first packet of pcap file
 
#### Code
```java
import com.jduan.pcaparser.*;

public static void main(String[] args) {
    Pcap pcap = new Pcap("sample.pcap");
    pcap.unpack();

    Iterator<Protocol> iter = pcap.iterator();
    Protocol eth = iter.next();
    if (eth instanceof Ethernet) {
        System.out.println("DHOST: " + eth.field(Ethernet.DHOST));
        System.out.println("SHOST: " + eth.field(Ethernet.SHOST));
        System.out.println("ETH_TYPE: " + eth.field(Ethernet.ETH_TYPE));
    }
}
```
 
#### Output
```text
DHOST: 00:26:62:2f:47:87
SHOST: 00:1d:60:b3:01:84
ETH_TYPE: 0x0800
```
