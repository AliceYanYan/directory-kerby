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
package org.apache.kerby.kerberos.kerb.admin.server.kpasswd.impl;

import org.apache.kerby.KOptions;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.server.kadmin.AdminServerContext;
import org.apache.kerby.kerberos.kerb.admin.server.kadmin.AdminServerSetting;
import org.apache.kerby.kerberos.kerb.admin.server.kpasswd.PasswdServerContext;
import org.apache.kerby.kerberos.kerb.admin.server.kpasswd.PasswdServerSetting;
import org.apache.kerby.kerberos.kerb.admin.server.kpasswd.PasswdServerUtil;
import org.apache.kerby.kerberos.kerb.client.KrbClient;
import org.apache.kerby.kerberos.kerb.transport.KdcNetwork;
import org.apache.kerby.kerberos.kerb.transport.TransportPair;
import org.apache.kerby.kerberos.kerb.transport.KrbTransport;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * A default passwd passwd implementation.
 */
public class DefaultInternalPasswdServerImpl extends AbstractInternalPasswdServer {
    private ExecutorService executor;
    private PasswdServerContext passwdServerContext;
    private AdminServerContext adminServerContext;
    private KdcNetwork network;

    public DefaultInternalPasswdServerImpl(PasswdServerSetting passwdSetting,
                                           AdminServerSetting adminServerSetting) {
        super(passwdSetting);
        adminServerContext = new AdminServerContext(adminServerSetting);

    }

    @Override
    protected void doStart() throws Exception {
        super.doStart();

        prepareHandler();

        executor = Executors.newCachedThreadPool();

        network = new KdcNetwork() {
            @Override
            protected void onNewTransport(KrbTransport transport) {
                DefaultPasswdServerHandler passwdHandler =
                    new DefaultPasswdServerHandler(passwdServerContext, adminServerContext, transport);
                executor.execute(passwdHandler);
            }
        };

        network.init();
        TransportPair tpair = PasswdServerUtil.getTransportPair(getSetting());
        network.listen(tpair);
        network.start();
    }

    private void prepareHandler() throws KrbException {
        passwdServerContext = new PasswdServerContext(getSetting());
        passwdServerContext.setIdentityService(getIdentityService());
        //acquire service key from kdc
        KrbClient krbClient = PasswdServerUtil.getKrbClient(
                            passwdServerContext.getPasswdServerSetting().getKrbConfig());
        krbClient.init();
        TgtTicket tgtTicket = PasswdServerUtil.getTgtTicket(krbClient, new KOptions());
        /** set service key.
         *  The tgt session key between kpasswd server and kdc
         *  is the service key of kpasswd service.
         */
        passwdServerContext.setServiceKey(tgtTicket.getSessionKey());

    }

    @Override
    protected void doStop() throws Exception {
        super.doStop();

        network.stop();

        executor.shutdownNow();
    }
}
