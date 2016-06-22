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
import org.apache.kerby.kerberos.kerb.client.KrbClient;
import org.apache.kerby.kerberos.kerb.client.KrbConfig;
import org.apache.kerby.kerberos.kerb.identity.backend.BackendConfig;
import org.apache.kerby.kerberos.kerb.identity.backend.IdentityBackend;
import org.apache.kerby.kerberos.kerb.identity.backend.MemoryIdentityBackend;
import org.apache.kerby.kerberos.kerb.transport.TransportPair;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;
import org.apache.kerby.kerberos.kerb.type.ticket.SgtTicket;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;

/**
 * KDC side utilities.
 */
public final class PasswdServerUtil {

    private PasswdServerUtil() { }

    /**
     * Get passwd configuration
     * @param confDir configuration directory
     * @return passwd configuration
     * @throws KrbException e.
     */
    public static PasswdServerConfig getPasswdServerConfig(File confDir) throws KrbException {
        File passwdConfFile = new File(confDir, "kpasswdServer.conf");
        if (passwdConfFile.exists()) {
            PasswdServerConfig passwdServerConfig = new PasswdServerConfig();
            try {
                passwdServerConfig.addKrb5Config(passwdConfFile);
            } catch (IOException e) {
                throw new KrbException("Can not load the passwd configuration file "
                        + passwdConfFile.getAbsolutePath());
            }
            return passwdServerConfig;
        }

        return null;
    }

    /**
     * Get backend configuration
     * @param confDir configuration directory
     * @return backend configuration
     * @throws KrbException e.
     */
    public static BackendConfig getBackendConfig(File confDir) throws KrbException {
        File backendConfigFile = new File(confDir, "kpasswdBackend.conf");
        if (backendConfigFile.exists()) {
            BackendConfig backendConfig = new BackendConfig();
            try {
                backendConfig.addIniConfig(backendConfigFile);
            } catch (IOException e) {
                throw new KrbException("Can not load the backend configuration file "
                        + backendConfigFile.getAbsolutePath());
            }
            return backendConfig;
        }

        return null;
    }

    /**
     * Get krb5 configuration
     * @param confDir configuration directory
     * @return passwd configuration
     * @throws KrbException e.
     */
    public static KrbConfig getKrbConfig(File confDir) throws KrbException {
        File krbConfFile = new File(confDir, "krb5.conf");
        if (krbConfFile.exists()) {
            KrbConfig krbConfig = new KrbConfig();
            try {
                krbConfig.addKrb5Config(krbConfFile);
            } catch (IOException e) {
                throw new KrbException("Can not load the krb5 configuration file "
                    + krbConfFile.getAbsolutePath());
            }
            return krbConfig;
        }

        return null;
    }

    /**
     * Init the identity backend from backend configuration.
     *
     * @throws KrbException e.
     * @param backendConfig backend configuration information
     * @return backend
     */
    public static IdentityBackend getBackend(
            BackendConfig backendConfig) throws KrbException {
        String backendClassName = backendConfig.getString(
                PasswdServerConfigKey.KDC_IDENTITY_BACKEND, true);
        if (backendClassName == null) {
            backendClassName = MemoryIdentityBackend.class.getCanonicalName();
        }

        Class<?> backendClass;
        try {
            backendClass = Class.forName(backendClassName);
        } catch (ClassNotFoundException e) {
            throw new KrbException("Failed to load backend class: "
                    + backendClassName);
        }

        IdentityBackend backend;
        try {
            backend = (IdentityBackend) backendClass.newInstance();
        } catch (InstantiationException | IllegalAccessException e) {
            throw new KrbException("Failed to create backend: "
                    + backendClassName);
        }

        backend.setConfig(backendConfig);
        backend.initialize();
        return backend;
    }

    /**
     * Get KDC network transport addresses according to KDC setting.
     * @param setting passwd setting
     * @return UDP and TCP addresses pair
     * @throws KrbException e
     */
    public static TransportPair getTransportPair(
            PasswdServerSetting setting) throws KrbException {
        TransportPair result = new TransportPair();

        int tcpPort = setting.checkGetPasswdTcpPort();
        if (tcpPort > 0) {
            result.tcpAddress = new InetSocketAddress(
                    setting.getPasswdHost(), tcpPort);
        }
        int udpPort = setting.checkGetPasswdUdpPort();
        if (udpPort > 0) {
            result.udpAddress = new InetSocketAddress(
                    setting.getPasswdHost(), udpPort);
        }

        return result;
    }

    public static EncryptionKey getServiceKey(PasswdServerContext passwdServerContext,
                             EncryptionType encryptionType, int kvno) throws KrbException {
        EncryptionKey serviceKey = passwdServerContext.getServiceKey();
        if (serviceKey.getKeyType() != encryptionType || serviceKey.getKvno() != kvno) {
            throw new KrbException("Service key does not match.");
        }
        return serviceKey;
    }

    public static KrbClient getKrbClient(File confDir) throws KrbException {
        KrbClient krbClient = null;
        if (confDir != null) {
            krbClient = new KrbClient(confDir);
        } else {
            krbClient = new KrbClient();
        }
        return krbClient;
    }

    public static KrbClient getKrbClient(KrbConfig krbConfig) throws KrbException {
        KrbClient krbClient = null;
        if (krbConfig != null) {
            krbClient = new KrbClient(krbConfig);
        } else {
            krbClient = new KrbClient();
        }
        return krbClient;
    }

    public static TgtTicket getTgtTicket(KrbClient krbClient, String principal,
                                         String password) {
        TgtTicket tgtTicket = null;
        try {
            krbClient.requestTgt(principal, password);
        } catch (KrbException e) {
            System.err.println("Requst Tgt ticket failed: " + e.getMessage());
            System.exit(1);
        }
        return tgtTicket;
    }

    public static SgtTicket getSgtTicket(KrbClient krbClient, TgtTicket tgtTicket) {
        SgtTicket sgtTicket = null;
        try {
            krbClient.requestSgt(tgtTicket, krbClient.getKrbConfig().getKdcHost());
        } catch (KrbException e) {
            System.err.println("Requst Sgt ticket failed: " + e.getMessage());
            System.exit(2);
        }
        return sgtTicket;
    }
}
