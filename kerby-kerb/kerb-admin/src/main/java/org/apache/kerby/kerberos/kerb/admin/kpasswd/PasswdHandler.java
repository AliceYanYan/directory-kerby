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
package org.apache.kerby.kerberos.kerb.admin.kpasswd;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.kpasswd.request.PasswdRequest;
import org.apache.kerby.kerberos.kerb.common.EncryptionUtil;
import org.apache.kerby.kerberos.kerb.type.EncKrbPrivPart;
import org.apache.kerby.kerberos.kerb.type.KrbPriv;
import org.apache.kerby.kerberos.kerb.type.ap.ApRep;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.KeyUsage;
import org.apache.kerby.kerberos.kerb.type.base.KrbMessageType;
import org.apache.kerby.xdr.util.HexUtil;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;

public abstract class PasswdHandler {

    /**
     * Init with krbcontext.
     *
     * @param context The krbcontext
     */
    public void init(PasswdContext context) {

    }

    /**
     * Handle the password server request.
     *
     * @param passwdRequest The password server request
     * @throws KrbException e
     */
    public void handleRequest(PasswdRequest passwdRequest) throws KrbException, IOException {
        passwdRequest.process();

        String request = "after password request process.";
        System.out.println(request);

        ByteBuffer message = null;
        if (passwdRequest.getTransport().isTcp()) {
            //plus a 4 bytes message length as head
            int tcpMessageLength = passwdRequest.getMessageLength() + 4;
            message = ByteBuffer.allocate(tcpMessageLength);
            message.putInt(tcpMessageLength);
        } else {
            message = ByteBuffer.allocate(passwdRequest.getMessageLength());
        }
        message.put(passwdRequest.getMessage());
        message.flip();

        try {
            sendMessage(passwdRequest, message);
            System.out.println("finish sending message");
        } catch (IOException e) {
            throw new KrbException("sending message failed", e);
        }
    }

    /**
     * Process the response message from kdc.
     *
     * @param passwdRequest The kpasswd request
     * @param responseMessage The message from kpasswd server
     * @throws KrbException e
     */
    public void onResponseMessage(PasswdRequest passwdRequest,
                                  ByteBuffer responseMessage) throws KrbException, IOException {
        System.out.println("Password Server receive message");

        //get off message length (short)
        responseMessage.getShort(); //message length

        //get off version number (short)
        responseMessage.getShort(); //version number

        //get off adReq length (short)
        short apReqLength = responseMessage.getShort();

        //get off apRep
        byte[] apRepBytes = new byte[apReqLength];
        responseMessage.get(apRepBytes, 0, apReqLength);
        ApRep apRep = new ApRep();
        apRep.decode(apRepBytes);

        //get session key
        //TODO: check if the session key is right
        EncryptionKey sessionKey = passwdRequest.getSgtTicket().getSessionKey();
        //verify apRep
        //EncAPRepPart encAPRepPart = EncryptionUtil.unseal(apRep.getEncryptedEncPart(),
            //sessionKey, KeyUsage.AP_REP_ENCPART, EncAPRepPart.class);

        //get off priv message
        byte[] privBytes = new byte[responseMessage.remaining()];
        responseMessage.get(privBytes, 0, responseMessage.remaining());
        KrbPriv privMessage = new KrbPriv();
        privMessage.decode(privBytes);

        //verify priv message
        if (privMessage.getPvno() != 5) {
            throw new KrbException("priv message version number does not match");
        }
        if (privMessage.getMsgType() != KrbMessageType.KRB_PRIV) {
            throw new KrbException("priv message type does not match");
        }

        //decrypt userdata
        EncKrbPrivPart encKrbPrivPart = EncryptionUtil.unseal(privMessage.getEncryptedEncPart(),
            sessionKey, KeyUsage.KRB_PRIV_ENCPART, EncKrbPrivPart.class);
        byte[] userData = encKrbPrivPart.getUserData();
        byte[] resultCode = Arrays.copyOfRange(userData, 0, 15);
        byte[] resultString = Arrays.copyOfRange(userData, 16, userData.length - 16);
        String code = HexUtil.bytesToHex(resultCode);
        String result = new String(resultString);
        System.out.println(code + ": " + result);

    }

    /**
     * Send message to password server.
     *
     * @param passwdRequest The change password request
     * @param requestMessage The request message to password server
     * @throws IOException e
     */
    protected abstract void sendMessage(PasswdRequest passwdRequest,
                                        ByteBuffer requestMessage) throws IOException;
}
