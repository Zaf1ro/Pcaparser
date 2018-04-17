# Pcaparser
[![experimental](http://badges.github.io/stability-badges/dist/experimental.svg)](http://github.com/badges/stability-badges)

Pcaparser let you programming with Pcap file, see examples in documentation

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
see more examples in DOCUMENTATION

## Documentation
http://pcaparser.readthedocs.io

## ABOUT
This code is based on TCP/IP, written, maintained and improved by Jason Duan. And it's being  by me.

## LICENSE
This code is under the [MIT Lience](https://opensource.org/licenses/MIT)

    
