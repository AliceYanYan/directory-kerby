package org.apache.haox.asn1.type;

import org.apache.haox.asn1.UniversalTag;

import java.io.IOException;

public class Asn1BitString extends Asn1Simple<byte[]>
{
    private int padding;

    public Asn1BitString() {
        this(null);
    }

    public Asn1BitString(byte[] value) {
        this(value, 0);
    }

    public Asn1BitString(byte[] value, int padding) {
        super(UniversalTag.BIT_STRING, value);
        this.padding = padding;
    }

    public void setPadding(int padding) {
        this.padding = padding;
    }

    public int getPadding() {
        return padding;
    }

    @Override
    protected int encodingBodyLength() {
        return getValue().length + 1;
    }

    @Override
    protected void toBytes() {
        byte[] bytes = new byte[encodingBodyLength()];
        bytes[0] = (byte)padding;
        System.arraycopy(getValue(), 0, bytes, 1, bytes.length - 1);
        setBytes(bytes);
    }

    @Override
    protected void toValue() throws IOException {
        byte[] bytes = getBytes();
        if (bytes.length < 1) {
            throw new IOException("Bad stream, zero bytes found for bitstring");
        }
        int paddingBits = bytes[0];
        validatePaddingBits(paddingBits);
        setPadding(paddingBits);

        byte[] newBytes = new byte[bytes.length - 1];
        if (bytes.length > 1) {
            System.arraycopy(bytes, 1, newBytes, 0, bytes.length - 1);
        }
        setValue(newBytes);
    }

    private void validatePaddingBits(int paddingBits) throws IOException {
        if (paddingBits < 0 || paddingBits > 7) {
            throw new IOException("Bad padding number: " + paddingBits + ", should be in [0, 7]");
        }
    }
}
