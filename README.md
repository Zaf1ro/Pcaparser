# Pcaparser
[![experimental](http://badges.github.io/stability-badges/dist/experimental.svg)](http://github.com/badges/stability-badges)

Pcaparser let you programming with Pcap file
<br /><br />

## Example
```java
Pcap pcap = new Pcap("eth.pcap");
pcap.unpack();

Iterator<Protocol> iter = pcap.iterator();
Protocol eth = iter.next();
if(eth instanceof Ethernet) {
    System.out.println("DHOST: " + eth.field(Ethernet.DHOST));
    System.out.println("SHOST: " + eth.field(Ethernet.SHOST));
    System.out.println("ETH_TYPE: " + eth.field(Ethernet.ETH_TYPE));
}
```
Output:
```text
DHOST: 00:26:62:2f:47:87
SHOST: 00:1d:60:b3:01:84
ETH_TYPE: 0x0800
```
see more examples in DOCUMENTATION
<br /><br />

## Documentation
http://pcaparser.readthedocs.io
<br /><br />

## ABOUT
This code is based on TCP/IP, written, maintained and improved by Jason Duan. And it's being  by me.
<br /><br />

## LICENSE
This code is under the [MIT Lience](https://opensource.org/licenses/MIT)

    
