package org.apache.kerberos.kerb.crypto.cksum;

import org.apache.kerberos.kerb.crypto.enc.EncryptProvider;
import org.apache.kerberos.kerb.crypto.key.KeyMaker;
import org.apache.kerberos.kerb.KrbException;

public abstract class AbstractKeyedCheckSumTypeHandler extends AbstractCheckSumTypeHandler {

    private KeyMaker keyMaker;

    public AbstractKeyedCheckSumTypeHandler(EncryptProvider encProvider, HashProvider hashProvider,
                                            int computeSize, int outputSize) {
        super(encProvider, hashProvider, computeSize, outputSize);
    }

    protected void keyMaker(KeyMaker keyMaker) {
        this.keyMaker = keyMaker;
    }

    protected KeyMaker keyMaker() {
        return keyMaker;
    }

    @Override
    public byte[] checksumWithKey(byte[] data,
                                  byte[] key, int usage) throws KrbException {
        return checksumWithKey(data, 0, data.length, key, usage);
    }

    @Override
    public byte[] checksumWithKey(byte[] data, int start, int len,
                                  byte[] key, int usage) throws KrbException {
        int outputSize = outputSize();

        byte[] tmp = doChecksumWithKey(data, start, len, key, usage);
        if (outputSize < tmp.length) {
            byte[] output = new byte[outputSize];
            System.arraycopy(tmp, 0, output, 0, outputSize);
            return output;
        } else {
            return tmp;
        }
    }

    protected byte[] doChecksumWithKey(byte[] data, int start, int len,
                                       byte[] key, int usage) throws KrbException {
        return new byte[0];
    }

    @Override
    public boolean verifyWithKey(byte[] data, byte[] key,
                                 int usage, byte[] checksum) throws KrbException {
        byte[] newCksum = checksumWithKey(data, key, usage);
        return checksumEqual(checksum, newCksum);
    }
}
