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
package org.apache.kerby.kerberos.kerb.admin.kpasswd.command;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.kpasswd.PasswdClient;
import org.apache.kerby.kerberos.kerb.admin.kpasswd.PasswdHandler;
import org.apache.kerby.kerberos.kerb.admin.kpasswd.PasswdUtil;
import org.apache.kerby.kerberos.kerb.admin.kpasswd.impl.DefaultPasswdHandler;
import org.apache.kerby.kerberos.kerb.admin.kpasswd.request.PasswdRequest;
import org.apache.kerby.kerberos.kerb.ccache.Credential;
import org.apache.kerby.kerberos.kerb.ccache.CredentialCache;
import org.apache.kerby.kerberos.kerb.transport.KrbNetwork;
import org.apache.kerby.kerberos.kerb.transport.KrbTransport;
import org.apache.kerby.kerberos.kerb.transport.TransportPair;
import org.apache.kerby.kerberos.kerb.type.kdc.EncAsRepPart;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;
import org.apache.kerby.kerberos.kerb.type.ticket.Ticket;

import java.io.File;
import java.io.IOException;

/**
 * Change Password Command
 */
public class ChangepwCommand extends KpasswdCommand {

    public static final String USAGE = "Usage: change_password <new_password> [principal-name]\n"
        + "\tprincipal name can be omitted if change its own password.\n"
        + "\tExample:\n"
        + "\t\tchange_password mypassword\n";

    public ChangepwCommand(PasswdClient passwdClient) {
        super(passwdClient);
    }

    @Override
    public void execute(String input) throws KrbException, IOException {
        String[] items = input.split("\\s+");

        if (items.length < 2 || items.length > 3) {
            System.err.println(USAGE);
            return;
        }

        String newPassword = items[1];
        String clientRealm = passwdClient.getPasswdConfig().getAdminRealm();
        String clientPrincipal = passwdClient.getPasswdConfig().getAdminHost();

        PasswdHandler passwdHandler = new DefaultPasswdHandler();

        String cacheFile = "krb5_ccache.cc";
        CredentialCache cCache = new CredentialCache();
        cCache.load(new File(cacheFile));

        TgtTicket tgt = null;
        for (Credential cred : cCache.getCredentials()) {
            Ticket tkt = cred.getTicket();
            if (cred.getClientName().getName() == clientPrincipal) {
                tgt = new TgtTicket(tkt, new EncAsRepPart(), cred.getClientName());
                break;
            }
            //System.out.println("Tkt server name: " + tkt.getSname().getName());
            //System.out.println("Tkt client name: " + cred.getClientName().getName());
            //System.out.println("Tkt encrypt type: " + tkt.getEncryptedEncPart().getEType().getName());
        }
        if (tgt == null) {
            throw new KrbException("Can not find tgt ticket");
        }

        PasswdRequest passwdRequest = new PasswdRequest(tgt);
        passwdRequest.setClientName(clientPrincipal);
        passwdRequest.setClientRealm(clientRealm);
        passwdRequest.setNewPassword(newPassword);
        if (items.length == 3) {
            passwdRequest.setIsTarget(false);
            passwdRequest.setTargetName(items[2]);
            passwdRequest.setTargetRealm(clientRealm); //target and client are in the same realm?
        }

        TransportPair tpair = PasswdUtil.getTransportPair(passwdClient.getSetting());
        KrbNetwork network = new KrbNetwork();
        network.setSocketTimeout(passwdClient.getSetting().getTimeout());
        KrbTransport transport;
        try {
            transport = network.connect(tpair);
        } catch (IOException e) {
            throw new KrbException("Failed to create transport", e);
        }
        passwdRequest.setTransport(transport);
        passwdHandler.handleRequest(passwdRequest);

    }
}
