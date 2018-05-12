package com.jduan;


public class Timer {
    private long startTime = 0;

    public void start() {
        if (startTime > 0) {
            System.out.println("Warn - Please End the timer before starting!!!");
            return;
        }
        startTime = System.currentTimeMillis();
    }

    public void end(String pre) {
        System.out.printf("%s: %s %s\n", pre, System.currentTimeMillis() - startTime, "millisec");
        startTime = 0;
    }
}
