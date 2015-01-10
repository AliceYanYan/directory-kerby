package org.apache.kerberos.kerb.crypto.enc;

import org.apache.kerberos.kerb.KrbErrorCode;
import org.apache.kerberos.kerb.crypto.BytesUtil;
import org.apache.kerberos.kerb.crypto.Confounder;
import org.apache.kerberos.kerb.crypto.cksum.HashProvider;
import org.apache.kerberos.kerb.crypto.key.DkKeyMaker;
import org.apache.kerberos.kerb.KrbException;

public abstract class KeKiEnc extends AbstractEncTypeHandler {

    public KeKiEnc(EncryptProvider encProvider,
                   HashProvider hashProvider) {
        super(encProvider, hashProvider);
    }

    @Override
    public int paddingSize() {
        return 0;
    }


    @Override
    protected void encryptWith(byte[] workBuffer, int[] workLens,
                               byte[] key, byte[] iv, int usage) throws KrbException {
        int confounderLen = workLens[0];
        int checksumLen = workLens[1];
        int inputLen = workLens[2];
        int paddingLen = workLens[3];

        byte[] Ke, Ki;
        byte[] constant = new byte[5];
        constant[0] = (byte) ((usage>>24)&0xff);
        constant[1] = (byte) ((usage>>16)&0xff);
        constant[2] = (byte) ((usage>>8)&0xff);
        constant[3] = (byte) (usage&0xff);
        constant[4] = (byte) 0xaa;
        Ke = ((DkKeyMaker) keyMaker()).dk(key, constant);
        constant[4] = (byte) 0x55;
        Ki = ((DkKeyMaker) keyMaker()).dk(key, constant);

        /**
         * Instead of E(Confounder | Checksum | Plaintext | Padding),
         * E(Confounder | Plaintext | Padding) | Checksum,
         * so need to adjust the workBuffer arrangement
         */

        byte[] tmpEnc = new byte[confounderLen + inputLen + paddingLen];
        // confounder
        byte[] confounder = Confounder.makeBytes(confounderLen);
        System.arraycopy(confounder, 0, tmpEnc, 0, confounderLen);

        // data
        System.arraycopy(workBuffer, confounderLen + checksumLen,
                tmpEnc, confounderLen, inputLen);

        // padding
        for (int i = confounderLen + inputLen; i < paddingLen; ++i) {
            tmpEnc[i] = 0;
        }

        // checksum & encrypt
        byte[] checksum;
        checksum = makeChecksum(Ki, tmpEnc, checksumLen);
        encProvider().encrypt(Ke, iv, tmpEnc);

        System.arraycopy(tmpEnc, 0, workBuffer, 0, tmpEnc.length);
        System.arraycopy(checksum, 0, workBuffer, tmpEnc.length, checksum.length);
    }

    @Override
    protected byte[] decryptWith(byte[] workBuffer, int[] workLens,
                                 byte[] key, byte[] iv, int usage) throws KrbException {
        int confounderLen = workLens[0];
        int checksumLen = workLens[1];
        int dataLen = workLens[2];

        byte[] Ke, Ki;
        byte[] constant = new byte[5];
        BytesUtil.int2bytes(usage, constant, 0, true);
        constant[4] = (byte) 0xaa;
        Ke = ((DkKeyMaker) keyMaker()).dk(key, constant);
        constant[4] = (byte) 0x55;
        Ki = ((DkKeyMaker) keyMaker()).dk(key, constant);

        // decrypt and verify checksum

        byte[] tmpEnc = new byte[confounderLen + dataLen];
        System.arraycopy(workBuffer, 0,
                tmpEnc, 0, confounderLen + dataLen);
        byte[] checksum = new byte[checksumLen];
        System.arraycopy(workBuffer, confounderLen + dataLen,
                checksum, 0, checksumLen);

        byte[] newChecksum;
        encProvider().decrypt(Ke, iv, tmpEnc);
        newChecksum = makeChecksum(Ki, tmpEnc, checksumLen);

        if (! checksumEqual(checksum, newChecksum)) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_BAD_INTEGRITY);
        }

        byte[] data = new byte[dataLen];
        System.arraycopy(tmpEnc, confounderLen, data, 0, dataLen);
        return data;
    }

    protected abstract byte[] makeChecksum(byte[] key, byte[] data, int hashSize)
            throws KrbException;
}
