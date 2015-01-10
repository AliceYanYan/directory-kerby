package org.apache.kerberos.kerb.spec;

import org.apache.haox.asn1.type.Asn1GeneralString;

/**
 KerberosString  ::= GeneralString -- (IA5String)
 */
public class KerberosString extends Asn1GeneralString {
    public KerberosString() {
    }

    public KerberosString(String value) {
        super(value);
    }
}
