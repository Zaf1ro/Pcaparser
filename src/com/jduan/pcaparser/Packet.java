package com.jduan.pcaparser;


public interface Packet {
    String field(int id);
    String type();      /* the type of current protocol */
    Packet next();      /* next layer protocol in one packet */

    String text();        /* info of current layer of protocol */
    void print();       /* print info of current layer of protocol */
    void printAll();    /* print all protocols of this packet */
}
