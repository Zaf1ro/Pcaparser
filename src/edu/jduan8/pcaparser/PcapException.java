package edu.jduan8.pcaparser;


public class PcapException extends Exception {
    public PcapException() {
        super();
    }

    public PcapException(String msg) {
        super(msg);
    }
}

class PcapIOException extends PcapException {
    public PcapIOException() {
        super();
    }

    public PcapIOException(String msg, String filepath) {
        // log function
        super(msg + filepath);
    }

    public PcapIOException(String msg, long pos) {
        super(msg +  Long.toString(pos));
    }
}