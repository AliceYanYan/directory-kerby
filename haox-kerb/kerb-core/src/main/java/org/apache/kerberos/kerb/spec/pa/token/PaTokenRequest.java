package org.apache.kerberos.kerb.spec.pa.token;

import org.apache.haox.asn1.type.Asn1FieldInfo;
import org.apache.kerberos.kerb.spec.KrbSequenceType;
import org.apache.kerberos.kerb.spec.common.KrbToken;

/**
 PA-TOKEN-REQUEST ::= SEQUENCE {
    token          [0]  OCTET STRING,
    tokenInfo      [1]  TokenInfo
 }
*/
public class PaTokenRequest extends KrbSequenceType {
    private static int TOKEN_INFO = 0;
    private static int TOKEN = 1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(TOKEN_INFO, TokenInfo.class),
            new Asn1FieldInfo(TOKEN, KrbToken.class)
    };

    public PaTokenRequest() {
        super(fieldInfos);
    }

    public KrbToken getToken() {
        return getFieldAs(TOKEN, KrbToken.class);
    }

    public void setToken(KrbToken token) {
        setFieldAs(TOKEN, token);
    }

    public String getTokenInfo() {
        return getFieldAsString(TOKEN_INFO);
    }

    public void setTokenInfo(TokenInfo tokenInfo) {
        setFieldAs(TOKEN_INFO, tokenInfo);
    }

}
