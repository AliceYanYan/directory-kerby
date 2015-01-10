package org.apache.kerberos.kerb.spec.common;

import org.apache.haox.asn1.type.Asn1FieldInfo;
import org.apache.haox.asn1.type.Asn1Integer;
import org.apache.haox.asn1.type.Asn1OctetString;
import org.apache.kerberos.kerb.spec.KrbSequenceType;

import java.util.Arrays;

/**
 Checksum        ::= SEQUENCE {
 cksumtype       [0] Int32,
 checksum        [1] OCTET STRING
 }
 */
public class CheckSum extends KrbSequenceType {
    private static int CKSUM_TYPE = 0;
    private static int CHECK_SUM = 1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
        new Asn1FieldInfo(CKSUM_TYPE, 0, Asn1Integer.class),
        new Asn1FieldInfo(CHECK_SUM, 1, Asn1OctetString.class)
    };

    public CheckSum() {
        super(fieldInfos);
    }

    public CheckSum(CheckSumType cksumType, byte[] checksum) {
        this();

        setCksumtype(cksumType);
        setChecksum(checksum);
    }

    public CheckSum(int cksumType, byte[] checksum) {
        this(CheckSumType.fromValue(cksumType), checksum);
    }

    public CheckSumType getCksumtype() {
        Integer value = getFieldAsInteger(CKSUM_TYPE);
        return CheckSumType.fromValue(value);
    }

    public void setCksumtype(CheckSumType cksumtype) {
        setFieldAsInt(CKSUM_TYPE, cksumtype.getValue());
    }

    public byte[] getChecksum() {
        return getFieldAsOctets(CHECK_SUM);
    }

    public void setChecksum(byte[] checksum) {
        setFieldAsOctets(CHECK_SUM, checksum);
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) return true;
        if (other == null || getClass() != other.getClass()) return false;

        CheckSum that = (CheckSum) other;

        if (getCksumtype() != that.getCksumtype()) return false;

        return Arrays.equals(getChecksum(), that.getChecksum());
    }

    public boolean isEqual(CheckSum other) {
        return this.equals(other);
    }

    public boolean isEqual(byte[] cksumBytes) {
        return Arrays.equals(getChecksum(), cksumBytes);
    }
}
