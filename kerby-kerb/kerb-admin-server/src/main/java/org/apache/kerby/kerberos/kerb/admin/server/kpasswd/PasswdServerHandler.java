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
package org.apache.kerby.kerberos.kerb.admin.server.kpasswd;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.kadmin.local.LocalKadmin;
import org.apache.kerby.kerberos.kerb.admin.kadmin.local.LocalKadminImpl;
import org.apache.kerby.kerberos.kerb.admin.server.kadmin.AdminServerContext;
import org.apache.kerby.kerberos.kerb.common.EncryptionUtil;
import org.apache.kerby.kerberos.kerb.request.ApRequest;
import org.apache.kerby.kerberos.kerb.type.EncKrbPrivPart;
import org.apache.kerby.kerberos.kerb.type.KrbPriv;
import org.apache.kerby.kerberos.kerb.type.ap.ApRep;
import org.apache.kerby.kerberos.kerb.type.ap.ApReq;
import org.apache.kerby.kerberos.kerb.type.ap.Authenticator;
import org.apache.kerby.kerberos.kerb.type.ap.EncAPRepPart;
import org.apache.kerby.kerberos.kerb.type.base.*;
import org.apache.kerby.kerberos.kerb.type.ticket.Ticket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.ByteBuffer;

/**
 * KDC handler to process client requests. Currently only one realm is supported.
 */
public class PasswdServerHandler {
    private static final Logger LOG = LoggerFactory.getLogger(PasswdServerHandler.class);
    private final PasswdServerContext passwdServerContext;
    private final AdminServerContext adminServerContext;

    /**
     * Constructor with passwd context.
     *
     * @param passwdServerContext passwd passwd context
     */
    public PasswdServerHandler(PasswdServerContext passwdServerContext,
                               AdminServerContext adminServerContext) {
        this.passwdServerContext = passwdServerContext;
        this.adminServerContext = adminServerContext;
        LOG.info("Passwd context realm:" + this.passwdServerContext.getPasswdRealm());
        LOG.info("Admin context realm:" + this.adminServerContext.getAdminRealm());
    }

    /**
     * Process the client request message.
     *
     * @throws KrbException e
     * @param receivedMessage The client request message
     * @param remoteAddress Address from remote side
     * @return The response message
     */
    public ByteBuffer handleMessage(ByteBuffer receivedMessage,
                                    InetAddress remoteAddress) throws KrbException, IOException {
        System.out.println("Password Server receive message");

        //get off message length (short)
        receivedMessage.getShort(); //message length

        //get off version number (short)
        receivedMessage.getShort(); //version number

        //get off adReq length (short)
        short apReqLength = receivedMessage.getShort();

        //get off apReq
        byte[] apReqBytes = new byte[apReqLength];
        receivedMessage.get(apReqBytes, 0, apReqLength);
        ApReq apReq = new ApReq();
        apReq.decode(apReqBytes);

        //get encrypt type and kvno
        EncryptionType encryptionType = apReq.getTicket().getEncryptedEncPart().getEType();
        int kvno = apReq.getTicket().getEncryptedEncPart().getKvno();

        //get server key
        EncryptionKey serviceKey = PasswdServerUtil.getServiceKey(passwdServerContext, encryptionType, kvno);

        //verify apReq
        ApRequest.validate(serviceKey, apReq);
        //ticket has been decrypt after the apreq validate.
        Ticket ticket = apReq.getTicket();
        Authenticator authenticator = EncryptionUtil.unseal(apReq.getEncryptedAuthenticator(),
            ticket.getEncPart().getKey(), KeyUsage.AP_REQ_AUTH, Authenticator.class);

        //check whether the client principal in the ticket is authorized to set/change the password
        if (authenticator.getCname() != ticket.getSname()) {
            throw new KrbException("client principal in the ticket is not authorized to set/change the password");
        }

        //check the initial flag
        if (!ticket.getEncPart().getFlags().isInitial()) {
            throw new KrbException("krb5-kpasswd-initial-flag-needed");
        }

        //get off priv message
        byte[] privBytes = new byte[receivedMessage.remaining()];
        receivedMessage.get(privBytes, 0, receivedMessage.remaining());
        KrbPriv privMessage = new KrbPriv();
        privMessage.decode(privBytes);

        //verify priv message
        if (privMessage.getPvno() != 5) {
            throw new KrbException("priv message version number does not match");
        }
        if (privMessage.getMsgType() != KrbMessageType.KRB_PRIV) {
            throw new KrbException("priv message type does not match");
        }

        //decrypt the new password
        EncKrbPrivPart encKrbPrivPart = EncryptionUtil.unseal(privMessage.getEncryptedEncPart(),
            authenticator.getSubKey(), KeyUsage.KRB_PRIV_ENCPART, EncKrbPrivPart.class);
        if (!encKrbPrivPart.getSAddress().equalsWith(remoteAddress)) {
            throw new KrbException("sender address does not match");
        }
        byte[] userData = encKrbPrivPart.getUserData();
        //TODO: isTarget
        String newPassword = userData.toString();

        //set new password
        LocalKadmin localKadmin = new LocalKadminImpl(adminServerContext.getAdminServerSetting());
        localKadmin.changePassword(authenticator.getCname().getName(), newPassword);
        System.out.println(authenticator.getCname().getName()
            + ": password has been changed successfully.");
        LOG.info(authenticator.getCname().getName()
            + ": password has been changed successfully");

        //generate reply message

        //genrete priv message
        byte[] resultCode = {(byte) 0x00, (byte) 0x00};
        String resultString = "request succeeds";
        ByteBuffer result = ByteBuffer.allocate(16 + resultString.length());
        result.put(resultCode);
        result.put(resultString.getBytes());
        EncKrbPrivPart replyPrivPart = new EncKrbPrivPart();
        replyPrivPart.setUserData(result.array());
        replyPrivPart.setSAddress(new HostAddress(InetAddress.getLocalHost()));
        KrbPriv replyPrivMessage = new KrbPriv();
        replyPrivMessage.setEncPart(replyPrivPart);
        //get subsession key from authenticator
        EncryptionKey subSessionKey = authenticator.getSubKey();
        EncryptedData encryptedData = EncryptionUtil.seal(replyPrivPart,
            subSessionKey, KeyUsage.KRB_PRIV_ENCPART);
        replyPrivMessage.setEncryptedEncPart(encryptedData);

        //gerenate AP_REP
        EncAPRepPart encAPRepPart = new EncAPRepPart();
        encAPRepPart.setCtime(authenticator.getCtime());
        encAPRepPart.setCusec(authenticator.getCusec());
        encAPRepPart.setSeqNumber(Integer.valueOf(authenticator.getSeqNumber()));
        encAPRepPart.setSubkey(authenticator.getSubKey());

        EncryptedData replyEncData = EncryptionUtil.seal(encAPRepPart,
            ticket.getEncPart().getKey(), KeyUsage.AP_REP_ENCPART);
        ApRep apRep = new ApRep();
        apRep.setEncRepPart(encAPRepPart);
        apRep.setEncryptedEncPart(replyEncData);

        int messageLength = 6 + apRep.encodingLength() + replyPrivMessage.encodingLength();
        ByteBuffer responseMessage = ByteBuffer.allocate(messageLength);
        responseMessage.putShort((short) messageLength);
        responseMessage.putShort((short) 5);
        responseMessage.putShort((short) apRep.encodingLength());
        responseMessage.put(apRep.encode());
        responseMessage.put(replyPrivMessage.encode());
        receivedMessage.flip();

        System.out.println("Password server handled message.");

        return responseMessage;
    }
}
