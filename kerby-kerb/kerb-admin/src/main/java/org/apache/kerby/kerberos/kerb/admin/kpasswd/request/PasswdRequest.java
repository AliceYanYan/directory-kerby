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

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.common.EncryptionUtil;
import org.apache.kerby.kerberos.kerb.transport.KrbTransport;
import org.apache.kerby.kerberos.kerb.type.EncKrbPrivPart;
import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.apache.kerby.kerberos.kerb.type.KrbPriv;
import org.apache.kerby.kerberos.kerb.type.ap.ApOption;
import org.apache.kerby.kerberos.kerb.type.ap.ApOptions;
import org.apache.kerby.kerberos.kerb.type.ap.ApReq;
import org.apache.kerby.kerberos.kerb.type.ap.Authenticator;
import org.apache.kerby.kerberos.kerb.type.base.*;
import org.apache.kerby.kerberos.kerb.type.ticket.SgtTicket;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.ByteBuffer;

/**
 * Password request deals with change password and set password.
 * However, change password does not care about original password.
 * Therefore, only one kind of password requst is enough.
 * 'client' means passwordClient in this file.
 * Not exactly the one who actually need the password changed.
 */
public class PasswdRequest {
    private KrbTransport transport;
    private ByteBuffer message;
    private int messageLength;

    private SgtTicket sgtTicket;
    private String clientName; //client name in its principal
    private String clientRealm; //where client registered

    private boolean isTarget; //true: client is target; false: client is not target
    private String targetName; //source which ask for change password, not the passwd client.
    private String targetRealm; //source which ask for change password.
    private String newPassword; //new password


    private ApReq apReq;
    private KrbPriv privMessage;
    private InetAddress senderAddress;

    public PasswdRequest(SgtTicket sgtTicket) throws KrbException {
        this.sgtTicket = sgtTicket;
        isTarget = true;
    }

    public void setIsTarget(boolean isTarget) {
        this.isTarget = isTarget;
    }
    public ApReq getApReq() throws KrbException {
        if (this.apReq == null) {
            this.apReq = makeApReq();
        }
        return this.apReq;
    }

    public void setPrivMessage(KrbPriv privMessage) {
        this.privMessage = privMessage;
    }

    public KrbPriv getPrivMessage() throws KrbException {
        if (this.privMessage == null) {
            this.privMessage = makePrivMessage();
        }
        return this.privMessage;
    }
    public void setTransport(KrbTransport transport) {
        this.transport = transport;
    }

    public KrbTransport getTransport() {
        return transport;
    }

    public SgtTicket getSgtTicket() {
        return sgtTicket;
    }

    public void process() throws KrbException, IOException {
        makeApReq();
        makePrivMessage();

        //encode messageLength, protocolVersionNumber, apReq and privMessage
        messageLength = 6 + apReq.encodingLength() + privMessage.encodingLength();
        this.message = ByteBuffer.allocate(messageLength);
        this.message.putShort((short) messageLength); //short type
        this.message.putShort((short) 5); //version number, short type
        this.message.putShort((short) apReq.encodingLength());
        this.message.put(apReq.encode());
        this.message.put(privMessage.encode());
        this.message.flip();
    }

    public ByteBuffer getMessage() {
        return message;
    }

    public int getMessageLength() {
        return messageLength;
    }

    private ApReq makeApReq() throws KrbException {
        ApReq apReq = new ApReq();

        apReq.setMsgType(KrbMessageType.AP_REQ);
        ApOptions apOptions = new ApOptions();
        apOptions.setFlag(ApOption.USE_SESSION_KEY);
        apReq.setApOptions(apOptions);
        apReq.setTicket(sgtTicket.getTicket());
        Authenticator authenticator = makeAuthenticator();
        EncryptionKey sessionKey = sgtTicket.getSessionKey();
        EncryptedData encAuthData = EncryptionUtil.seal(authenticator,
            sessionKey, KeyUsage.AP_REQ_AUTH);
        apReq.setEncryptedAuthenticator(encAuthData);
        apReq.setAuthenticator(authenticator);

        return apReq;
    }

    private Authenticator makeAuthenticator() {
        Authenticator authenticator = new Authenticator();
        authenticator.setAuthenticatorVno(5);
        PrincipalName cn = new PrincipalName(clientName);
        cn.setRealm(clientRealm);
        authenticator.setCname(cn); // client's principal identifier
        authenticator.setCrealm(clientRealm);
        authenticator.setCtime(KerberosTime.now());
        authenticator.setCusec(0);
        //authenticator.setSeqNumber(); random choose?
        authenticator.setSubKey(sgtTicket.getSessionKey());

        return authenticator;
    }

    private KrbPriv makePrivMessage() throws KrbException {
        /** targetName and targetRealm is choosable.
         *  consider change the makePrivMessage function into a new class.
         */
        KrbPriv privMessage = new KrbPriv();
        privMessage.setMsgType(KrbMessageType.KRB_PRIV);

        EncKrbPrivPart encKrbPrivPart =  new EncKrbPrivPart();
        byte[] userData = getUserData();
        encKrbPrivPart.setUserData(userData);
        encKrbPrivPart.setSAddress(new HostAddress(senderAddress));
        //encKrbPrivPart.setTimeStamp(KerberosTime.now());
        //encKrbPrivPart.setUsec(0);
        privMessage.setEncPart(encKrbPrivPart);
        EncryptedData encryptedData = EncryptionUtil.seal(encKrbPrivPart,
            sgtTicket.getSessionKey(), KeyUsage.KRB_PRIV_ENCPART);
        privMessage.setEncryptedEncPart(encryptedData);

        return privMessage;
    }

    private byte[] getUserData() { //TODO: change to ASN1 encoding!
        int length = newPassword.length();
        if (!isTarget) {
            length += targetName.length();
            length += targetRealm.length();
        }
        ByteBuffer buffer = ByteBuffer.allocate(length);
        buffer.put(newPassword.getBytes());
        if (!isTarget) {
            buffer.put(targetName.getBytes());
            buffer.put(targetRealm.getBytes());
        }

        return buffer.array();
    }

    public void setClientName(String clientName) {
        this.clientName = clientName;
    }

    public void setClientRealm(String clientRealm) {
        this.clientRealm = clientRealm;
    }

    public void setTargetName(String targetName) {
        this.targetName = targetName;
    }

    public String getTargetName() {
        return targetName;
    }

    public void setTargetRealm(String targetRealm) {
        this.targetRealm = targetRealm;
    }

    public String getTargetRealm() {
        return targetRealm;
    }

    public void setNewPassword(String newPassword) {
        this.newPassword = newPassword;
    }

    public void setSenderAddress(InetAddress senderAddress) {
        this.senderAddress = senderAddress;
    }
}