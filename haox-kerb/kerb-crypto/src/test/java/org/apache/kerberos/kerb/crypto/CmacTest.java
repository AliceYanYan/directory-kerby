package org.apache.kerberos.kerb.crypto;

import org.apache.kerberos.kerb.KrbException;
import org.apache.kerberos.kerb.crypto.enc.EncryptProvider;
import org.apache.kerberos.kerb.crypto.enc.provider.Camellia128Provider;
import org.junit.Assert;
import org.junit.Test;

public class CmacTest {

    /* All examples use the following Camellia-128 key. */
    static String keyBytes = "2b7e151628aed2a6" +
            "abf7158809cf4f3c";

    /* Example inputs are this message truncated to 0, 16, 40, and 64 bytes. */
    static String inputBytes = "6bc1bee22e409f96" +
            "e93d7e117393172a" +
            "ae2d8a571e03ac9c" +
            "9eb76fac45af8e51" +
            "30c81c46a35ce411" +
            "e5fbc1191a0a52ef" +
            "f69f2445df4f9b17" +
            "ad2b417be66c3710";

    /* Expected result of CMAC on empty inputBytes. */
    static String cmac1 = "ba925782aaa1f5d9" +
            "a00f89648094fc71";

    /* Expected result of CMAC on first 16 bytes of inputBytes. */
    static String cmac2 = "6d962854a3b9fda5" +
            "6d7d45a95ee17993";

    /* Expected result of CMAC on first 40 bytes of inputBytes. */
    static String cmac3 = "5c18d119ccd67661" +
            "44ac1866131d9f22";

    /* Expected result of CMAC on all 64 bytes of inputBytes. */
    static String cmac4 = "c2699a6eba55ce9d" +
            "939a8a4e19466ee9";


    @Test
    public void testCmac() throws KrbException, KrbException {
        byte[] key = TestUtil.hex2bytes(keyBytes);
        byte[] input = TestUtil.hex2bytes(inputBytes);
        EncryptProvider encProvider = new Camellia128Provider();
        byte[] result;

        // test 1
        result = Cmac.cmac(encProvider, key, input, 0, 0);
        Assert.assertArrayEquals("Test 1", TestUtil.hex2bytes(cmac1), result);

        // test 2
        result = Cmac.cmac(encProvider, key, input, 0, 16);
        Assert.assertArrayEquals("Test 2", TestUtil.hex2bytes(cmac2), result);

        // test 3
        result = Cmac.cmac(encProvider, key, input, 0, 40);
        Assert.assertArrayEquals("Test 3", TestUtil.hex2bytes(cmac3), result);

        // test 4
        result = Cmac.cmac(encProvider, key, input, 0, 64);
        Assert.assertArrayEquals("Test 4", TestUtil.hex2bytes(cmac4), result);
    }
}
