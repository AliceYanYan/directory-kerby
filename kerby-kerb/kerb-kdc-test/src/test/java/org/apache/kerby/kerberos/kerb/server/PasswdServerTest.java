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
package org.apache.kerby.kerberos.kerb.server;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.server.kpasswd.PasswdServer;
import org.apache.kerby.kerberos.kerb.admin.server.kpasswd.PasswdServerConfig;
import org.junit.Test;

import java.io.File;
import java.net.URI;
import java.net.URL;

/**
 * To test passwd server inter act with kdc.
 */
public class PasswdServerTest extends KdcTestBase {


    @Test
    public void passwdServerLoginTest() throws Exception {
        URL passwdServerUrl = PasswdServerTest.class.getResource("/kpasswdServer.conf");
        URL backendUrl = PasswdServerTest.class.getResource("/kpasswdBackend.conf");
        URL krbUrl = PasswdServerTest.class.getResource("/krb5.conf");
        PasswdServer passwdServer = new PasswdServer(passwdServerUrl.toURI(), backendUrl.toURI(), krbUrl.toURI());
        PasswdServerConfig passwdServerConfig = passwdServer.getPasswdServerConfig();

        passwdServer.setPasswdHost(passwdServerConfig.getPasswdHost());
        passwdServer.setAllowTcp(true);
        passwdServer.setAllowUdp(true); /**change password protocol allow both tcp and udp*/
        passwdServer.setPasswdServerPort(passwdServerConfig.getPasswdPort());

        try {
            passwdServer.login(getKrbClient());
        } catch (KrbException e) {
            System.err.println("Errors occurred when password server login:  " + e.getMessage());
            System.exit(2);
        }
    }




}
