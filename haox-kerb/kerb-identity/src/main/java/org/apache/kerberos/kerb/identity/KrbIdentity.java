package org.apache.kerberos.kerb.identity;

import org.apache.kerberos.kerb.spec.KerberosTime;
import org.apache.kerberos.kerb.spec.common.EncryptionKey;
import org.apache.kerberos.kerb.spec.common.EncryptionType;
import org.apache.kerberos.kerb.spec.common.PrincipalName;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class KrbIdentity {
    private String principalName;
    private PrincipalName principal;
    private int keyVersion = 1;
    private int kdcFlags = 0;
    private boolean disabled = false;
    private boolean locked = false;
    private KerberosTime expireTime = KerberosTime.NEVER;
    private KerberosTime createdTime = KerberosTime.now();

    private Map<EncryptionType, EncryptionKey> keys =
            new HashMap<EncryptionType, EncryptionKey>();

    public KrbIdentity(String principalName) {
        this.principalName = principalName;
        this.principal = new PrincipalName(principalName);
    }

    public String getPrincipalName() {
        return principalName;
    }

    public void setPrincipal(PrincipalName principal) {
        this.principal = principal;
    }

    public PrincipalName getPrincipal() {
        return principal;
    }

    public void setKeyVersion(int keyVersion) {
        this.keyVersion = keyVersion;
    }

    public void setKdcFlags(int kdcFlags) {
        this.kdcFlags = kdcFlags;
    }

    public void setDisabled(boolean disabled) {
        this.disabled = disabled;
    }

    public void setLocked(boolean locked) {
        this.locked = locked;
    }

    public void setExpireTime(KerberosTime expireTime) {
        this.expireTime = expireTime;
    }

    public KerberosTime getExpireTime() {
        return expireTime;
    }

    public KerberosTime getCreatedTime() {
        return createdTime;
    }

    public void setCreatedTime(KerberosTime createdTime) {
        this.createdTime = createdTime;
    }

    public boolean isDisabled() {
        return disabled;
    }

    public boolean isLocked() {
        return locked;
    }

    public void addKey(EncryptionKey encKey) {
        keys.put(encKey.getKeyType(), encKey);
    }

    public void addKeys(List<EncryptionKey> encKeys) {
        for (EncryptionKey key : encKeys) {
            keys.put(key.getKeyType(), key);
        }
    }

    public Map<EncryptionType, EncryptionKey> getKeys() {
        return keys;
    }

    public EncryptionKey getKey(EncryptionType encType) {
        return keys.get(encType);
    }

    public int getKdcFlags() {
        return kdcFlags;
    }

    public int getKeyVersion() {
        return keyVersion;
    }
}
