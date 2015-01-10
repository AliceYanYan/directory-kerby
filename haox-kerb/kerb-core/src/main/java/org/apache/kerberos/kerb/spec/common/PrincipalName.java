package org.apache.kerberos.kerb.spec.common;

import org.apache.haox.asn1.type.Asn1FieldInfo;
import org.apache.haox.asn1.type.Asn1Integer;
import org.apache.kerberos.kerb.spec.KerberosStrings;
import org.apache.kerberos.kerb.spec.KrbSequenceType;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 PrincipalName   ::= SEQUENCE {
 name-type       [0] Int32,
 name-string     [1] SEQUENCE OF KerberosString
 }
 */
public class PrincipalName extends KrbSequenceType {
    private String realm;

    private static int NAME_TYPE = 0;
    private static int NAME_STRING = 1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(NAME_TYPE, Asn1Integer.class),
            new Asn1FieldInfo(NAME_STRING, KerberosStrings.class)
    };

    public PrincipalName() {
        super(fieldInfos);
    }

    public PrincipalName(String nameString) {
        this();
        setNameType(NameType.NT_PRINCIPAL);
        fromNameString(nameString);
    }

    public PrincipalName(List<String> nameStrings, NameType type) {
        this();
        setNameStrings(nameStrings);
        setNameType(type);
    }

    public NameType getNameType() {
        Integer value = getFieldAsInteger(NAME_TYPE);
        return NameType.fromValue(value);
    }

    public void setNameType(NameType nameType) {
        setFieldAsInt(NAME_TYPE, nameType.getValue());
    }

    public List<String> getNameStrings() {
        KerberosStrings krbStrings = getFieldAs(NAME_STRING, KerberosStrings.class);
        if (krbStrings != null) {
            return krbStrings.getAsStrings();
        }
        return Collections.EMPTY_LIST;
    }

    public void setNameStrings(List<String> nameStrings) {
        setFieldAs(NAME_STRING, new KerberosStrings(nameStrings));
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }

    public String getRealm() {
        return this.realm;
    }

    public String getName() {
        return makeSingleName();
    }

    private String makeSingleName() {
        List<String> names = getNameStrings();
        StringBuilder sb = new StringBuilder();
        boolean isFirst = true;
        for (String name : names) {
            sb.append(name);
            if (isFirst && names.size() > 1) {
                sb.append('/');
            }
            isFirst = false;
        }

        String realm = getRealm();
        if (realm != null && !realm.isEmpty()) {
            sb.append('@');
            sb.append(realm);
        }

        return sb.toString();
    }

    @Override
    public String toString() {
        return getName();
    }

    @Override
    public int hashCode() {
        return getName().hashCode();
    }

    @Override
    public boolean equals(Object other) {
        if (other == null) {
            return false;
        } else if (this == other) {
            return true;
        } else if (other instanceof String) {
            String otherPrincipal = (String) other;
            String thisPrincipal = getName();
            return thisPrincipal.equals(otherPrincipal);
        } else if (! (other instanceof PrincipalName)) {
            return false;
        }

        PrincipalName otherPrincipal = (PrincipalName) other;
        if (getNameType() != ((PrincipalName) other).getNameType()) {
            return false;
        }

        return getName().equals(otherPrincipal.getName());
    }

    private void fromNameString(String nameString) {
        String tmpRealm = null;
        List<String> nameStrings;
        int pos = nameString.indexOf('@');
        String nameParts = nameString;
        if (pos != -1) {
            nameParts = nameString.substring(0, pos);
            tmpRealm = nameString.substring(pos + 1);
        }
        String parts[] = nameParts.split("\\/");
        nameStrings = Arrays.asList(parts);

        setNameStrings(nameStrings);
        setRealm(tmpRealm);
    }

    public static String extractRealm(String principal) {
        int pos = principal.indexOf('@');

        if (pos > 0) {
            return principal.substring(pos + 1);
        }

        throw new IllegalArgumentException("Not a valid principal, missing realm name");
    }


    public static String extractName(String principal) {
        int pos = principal.indexOf('@');

        if (pos < 0) {
            return principal;
        }

        return principal.substring(0, pos);
    }

    public static String makeSalt(PrincipalName principalName) {
        StringBuilder salt = new StringBuilder();
        if (principalName.getRealm() != null) {
            salt.append(principalName.getRealm().toString());
        }
        List<String> nameStrings = principalName.getNameStrings();
        for (String ns : nameStrings) {
            salt.append(ns);
        }
        return salt.toString();
    }

}
