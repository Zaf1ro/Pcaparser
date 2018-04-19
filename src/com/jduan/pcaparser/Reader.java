package com.jduan.pcaparser;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteOrder;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;


public class Reader {
    private String filePath;
    private long fileSize;

    /* NIO */
    private long offset;
    private RandomAccessFile aFile;
    private FileChannel fChannel;

    Reader(String filepath) {
        filePath = filepath;
        try {
            initNIO();
        } catch (PcapIOException e) {
            e.printStackTrace();
        }
    }

    public boolean isRemaining() {
        return offset < fileSize;
    }

    void fill(byte[] target) {
        int len = target.length;
        assert (offset + len < fileSize);
        MappedByteBuffer zBuffer = null;
        try {
            zBuffer = zRead(len);
        } catch (PcapIOException e) {
            e.printStackTrace();
        }

        assert (zBuffer != null);
        offset += len;
        zBuffer.get(target);
    }

    MappedByteBuffer read(long size) {
        assert offset + size < fileSize;
        System.out.printf("%d\n", offset);

        MappedByteBuffer zBuffer = null;
        try {
            zBuffer = zRead(size);
        } catch (PcapIOException e) {
            e.printStackTrace();
        }

        offset += size;
        return zBuffer;
    }

    MappedByteBuffer readAll() {
        return read(fileSize);
    }

    private void initNIO() throws PcapIOException {
        try {
            aFile = new RandomAccessFile(filePath, "r");
            fChannel = aFile.getChannel();
            fileSize = fChannel.size();
        } catch (IOException e) {
            throw new PcapIOException("Cant find the file: ", filePath);
        }
    }

    private MappedByteBuffer zRead(long size) throws PcapIOException {
        MappedByteBuffer zBuffer;
        try {
            zBuffer = fChannel.map(FileChannel.MapMode.READ_ONLY, offset, size);
            zBuffer.load();
        } catch (IOException e) {
            throw new PcapIOException("Cant read the file at: ", offset);
        }
        zBuffer.order(ByteOrder.LITTLE_ENDIAN);
        return zBuffer;
    }

    public void close() throws PcapException {
        try {
            if (aFile != null) {
                aFile.close();
            }
        } catch (IOException e) {
            throw new PcapIOException("Cant close file: ", filePath);
        }
    }
}
