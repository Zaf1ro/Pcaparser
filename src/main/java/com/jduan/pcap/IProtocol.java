package com.jduan.pcap;


/**
 * This interface provides uniform, read-only access to
 * the fields of the <tt>Protocol</tt>.
 *
 * @author  Jiaxu Duan
 * @since   5/12/18
 */
interface IProtocol {
    String field(int id);

    String type();      /* the type of current protocol */

    Protocol next();    /* next layer protocol in one packet */

    String text();      /* info of current layer of protocol */

    void print();       /* print info of current layer of protocol */

    void printAll();    /* print all protocols of this packet */
}
