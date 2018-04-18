# Print Pcap Example
This example uses Pcaparser to read in a pcap file and print out each field of header in pcap file
 
#### Code
```java
import com.jduan.pcaparser.*;

public static void main(String[] args) {
    Pcap pcap = new Pcap("sample.pcap");
    pcap.unpack();
    System.out.println("MAGIC: " + pcap.field(Pcap.MAGIC));
    System.out.println("V_MAJOR: " + pcap.field(Pcap.V_MAJOR));
    System.out.println("V_MINOR: " + pcap.field(Pcap.V_MINOR));
    System.out.println("THISZONE: " + pcap.field(Pcap.THISZONE));
    System.out.println("SIGFIGS: " + pcap.field(Pcap.SIGFIGS));
    System.out.println("SNAPLEN: " + pcap.field(Pcap.SNAPLEN));
    System.out.println("LINKTYPE: " + pcap.field(Pcap.LINKTYPE));
}
```
 
#### Example Output
```text
MAGIC: 0xd4c3b2a1
V_MAJOR: 2
V_MINOR: 4
THISZONE: 0
SIGFIGS: 0
SNAPLEN: 2000
LINKTYPE: 1
```