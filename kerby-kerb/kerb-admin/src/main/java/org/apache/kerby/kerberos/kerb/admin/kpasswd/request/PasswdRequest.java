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
package org.apache.kerby.kerberos.kerb.admin.kpasswd.request;

import org.apache.kerby.kerberos.kerb.admin.tool.PasswdReq;
import org.apache.kerby.kerberos.kerb.common.EncryptionUtil;
import org.apache.kerby.kerberos.kerb.transport.KrbTransport;
import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.apache.kerby.kerberos.kerb.type.ap.ApOptions;
import org.apache.kerby.kerberos.kerb.type.ap.ApReq;
import org.apache.kerby.kerberos.kerb.type.ap.Authenticator;
import org.apache.kerby.kerberos.kerb.type.base.EncryptedData;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.KeyUsage;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;

/**
 * There is only one kind of password request,
 * that is the change password request.
 * 'client' means passwordClient in this file.
 * Not exactly the one who actually need the password changed.
 */
public class PasswdRequest {
    private KrbTransport transport;

    private String clientName; //client name in its principal
    private String clientRealm; //where client registered





    /*private String sourcePrincipal; //source which ask for change password, not really the passwd client.
    private String sourceRealm; //source which ask for change password.
    private String newPassword; // new password
    */

    private ApReq apReq;
    //private PrivMessage privMessage;
    private PasswdReq passwdReq; //later when Priv_Message finish, change it into PrivMessage

    public void setApReq(ApReq apReq) {
        this.apReq = apReq;
    }

    public ApReq getApReq() {
        if (this.apReq == null) {
            this.apReq = makeApReq();
        }
        return this.apReq;
    }

    public void setpasswdReq(PasswdReq passwdReq) {
        this.passwdReq = passwdReq;
    }

    public PasswdReq getPasswdReq() {
        return passwdReq;
    }
    public void setTransport(KrbTransport transport) {
        this.transport = transport;
    }

    public KrbTransport getTransport() {
        return transport;
    }

    public void process() {

    }

    private ApReq makeApReq() {
        ApReq apReq = new ApReq();

        Authenticator authenticator = makeAuthenticator();
        EncryptionKey sessionKey = tgt.getSessionKey();
        EncryptedData authnData = EncryptionUtil.seal(authenticator,
            sessionKey, KeyUsage.TGS_REQ_AUTH);
        apReq.setEncryptedAuthenticator(authnData);
        apReq.setAuthenticator(authenticator);
        apReq.setTicket(tgt.getTicket());
        ApOptions apOptions = new ApOptions();
        apReq.setApOptions(apOptions);

        return apReq;
    }

    private Authenticator makeAuthenticator() {
        Authenticator authenticator = new Authenticator();
        authenticator.setAuthenticatorVno(5);
        authenticator.setCname(new PrincipalName(clientName)); // client's principal identifier
        authenticator.setCrealm(clientRealm);
        authenticator.setCtime(KerberosTime.now());
        authenticator.setCusec(0);
        authenticator.setSubKey(tgt.getSessionKey());

        KdcReqBody reqBody = getReqBody();
        CheckSum checksum = CheckSumUtil.seal(reqBody, null,
            tgt.getSessionKey(), KeyUsage.TGS_REQ_AUTH_CKSUM);
        authenticator.setCksum(checksum);

        return authenticator;
    }
}