package org.apache.haox.transport.buffer;

import java.nio.ByteBuffer;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

public class TransBuffer {

    private BlockingQueue<ByteBuffer> bufferQueue;

    public TransBuffer() {
        bufferQueue = new ArrayBlockingQueue<ByteBuffer>(2);
    }

    public void write(ByteBuffer buffer) {
        bufferQueue.add(buffer);
    }

    public void write(byte[] buffer) {
        write(ByteBuffer.wrap(buffer));
    }

    public ByteBuffer read() {
        return bufferQueue.poll();
    }

    public boolean isEmpty() {
        return bufferQueue.isEmpty();
    }
}
