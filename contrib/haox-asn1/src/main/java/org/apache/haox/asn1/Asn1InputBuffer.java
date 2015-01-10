package org.apache.haox.asn1;

import org.apache.haox.asn1.type.AbstractAsn1Type;
import org.apache.haox.asn1.type.Asn1Item;
import org.apache.haox.asn1.type.Asn1Type;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Asn1 decoder
 */
public class Asn1InputBuffer {
    private final LimitedByteBuffer limitedBuffer;

    public Asn1InputBuffer(byte[] bytes) {
        this(new LimitedByteBuffer(bytes));
    }

    public Asn1InputBuffer(ByteBuffer byteBuffer) {
        this(new LimitedByteBuffer(byteBuffer));
    }

    public Asn1InputBuffer(LimitedByteBuffer limitedByteBuffer) {
        this.limitedBuffer = limitedByteBuffer;
    }

    public Asn1Type read() throws IOException {
        if (! limitedBuffer.available()) {
            return null;
        }
        Asn1Item one = AbstractAsn1Type.decodeOne(limitedBuffer);
        if (one.isSimple()) {
            one.decodeValueAsSimple();
        } else if (one.isCollection()) {
            one.decodeValueAsCollection();
        }
        if (one.isFullyDecoded()) {
            return one.getValue();
        }
        return one;
    }

    public void readBytes(byte[] bytes) throws IOException {
        limitedBuffer.readBytes(bytes);
    }

    public byte[] readAllLeftBytes() throws IOException {
        return limitedBuffer.readAllLeftBytes();
    }

    public void skipNext() throws IOException {
        if (limitedBuffer.available()) {
            AbstractAsn1Type.skipOne(limitedBuffer);
        }
    }

    public void skipBytes(int len) throws IOException {
        if (limitedBuffer.available()) {
            limitedBuffer.skip(len);
        }
    }
}
