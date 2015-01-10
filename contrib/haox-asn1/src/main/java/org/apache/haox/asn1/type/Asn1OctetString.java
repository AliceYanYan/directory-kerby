package org.apache.haox.asn1.type;

import org.apache.haox.asn1.LimitedByteBuffer;
import org.apache.haox.asn1.UniversalTag;

import java.io.IOException;

public class Asn1OctetString extends Asn1Simple<byte[]>
{
    public Asn1OctetString() {
        this(null);
    }

    public Asn1OctetString(byte[] value) {
        super(UniversalTag.OCTET_STRING, value);
    }

    @Override
    protected byte[] encodeBody() {
        return getValue();
    }

    @Override
    protected int encodingBodyLength() {
        return getValue().length;
    }

    @Override
    protected void decodeBody(LimitedByteBuffer content) throws IOException {
        setValue(content.readAllLeftBytes());
    }
}
