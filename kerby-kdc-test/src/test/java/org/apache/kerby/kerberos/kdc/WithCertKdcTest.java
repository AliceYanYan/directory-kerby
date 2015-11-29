/**
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */
package org.apache.kerby.kerberos.kdc;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.KrbRuntime;
import org.apache.kerby.kerberos.kerb.client.KrbPkinitClient;
import org.apache.kerby.kerberos.kerb.provider.PkiLoader;
import org.apache.kerby.kerberos.kerb.server.KdcConfigKey;
import org.apache.kerby.kerberos.kerb.server.KdcTestBase;
import org.apache.kerby.kerberos.kerb.type.ticket.SgtTicket;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;
import org.apache.kerby.kerberos.provider.pki.KerbyPkiProvider;
import org.junit.Before;
import org.junit.Test;

import java.io.InputStream;
import java.net.URL;
import java.security.PrivateKey;
import java.security.cert.Certificate;

import static org.assertj.core.api.Assertions.assertThat;

/**
 openssl genrsa -out cakey.pem 2048
 openssl req -key cakey.pem -new -x509 -out cacert.pem -days 3650
 vi extensions.kdc
 openssl genrsa -out kdckey.pem 2048
 openssl req -new -out kdc.req -key kdckey.pem
 env REALM=SH.INTEL.COM openssl x509 -req -in kdc.req -CAkey cakey.pem \
 -CA cacert.pem -out kdc.pem -days 365 -extfile extensions.kdc -extensions kdc_cert -CAcreateserial
 */
public class WithCertKdcTest extends KdcTestBase {
    private PkiLoader pkiLoader;
    private String clientPrincipal;
    private String serverPrincipal;
    private Certificate userCert;
    private PrivateKey userKey;
    private Certificate caCert;

    @Before
    public void setUp() throws Exception {
        KrbRuntime.setPkiProvider(new KerbyPkiProvider());
        pkiLoader = KrbRuntime.getPkiProvider().createPkiLoader();

        super.setUp();
    }

    @Override
    protected void configKdcSeverAndClient() {
        super.configKdcSeverAndClient();

        String pkinitIdentity = getClass().getResource("/kdccert.pem").getPath() + ","
                + getClass().getResource("/kdckey.pem").getPath();
        getKdcServer().getKdcConfig().setString(KdcConfigKey.PKINIT_IDENTITY, pkinitIdentity);
    }

    @Override
    protected void setUpClient() throws Exception {
        super.setUpClient();

        loadCredentials();
    }

    @Override
    protected void createPrincipals() throws KrbException {
        super.createPrincipals();
        //Anonymity support is not enabled by default.
        //To enable it, you must create the principal WELLKNOWN/ANONYMOUS
        getKdcServer().createPrincipal("WELLKNOWN/ANONYMOUS");
    }

    @Test
    public void testAnonymity() throws Exception {

        getKrbClient().init();

        URL url = getClass().getResource("/cacert.pem");
        TgtTicket tgt;
        KrbPkinitClient pkinitClient = new KrbPkinitClient(getKrbClient());
        try {
            tgt = pkinitClient.requestTgt(url.getPath());
        } catch (KrbException te) {
            assertThat(te.getMessage().contains("timeout")).isTrue();
            return;
        }
        assertThat(tgt).isNotNull();

        serverPrincipal = getServerPrincipal();
        SgtTicket tkt = getKrbClient().requestSgt(tgt, serverPrincipal);
        assertThat(tkt).isNotNull();
    }

    //@Test
    public void testKdc() throws Exception {
        assertThat(userCert).isNotNull();

        getKrbClient().init();

        TgtTicket tgt;
        KrbPkinitClient pkinitClient = new KrbPkinitClient(getKrbClient());
        try {
            tgt = pkinitClient.requestTgt(userCert, userKey);
        } catch (KrbException te) {
            assertThat(te.getMessage().contains("timeout")).isTrue();
            return;
        }
        assertThat(tgt).isNull();

        serverPrincipal = getServerPrincipal();
        SgtTicket tkt = getKrbClient().requestSgt(tgt, serverPrincipal);
        assertThat(tkt).isNull();
    }

    private void loadCredentials() throws KrbException {
        InputStream res = getClass().getResourceAsStream("/usercert.pem");
        userCert = pkiLoader.loadCerts(res).iterator().next();

        res = getClass().getResourceAsStream("/userkey.pem");
        userKey = pkiLoader.loadPrivateKey(res, null);
    }
}