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
package org.apache.kerby.kerberos.kerb.admin;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.kpasswd.PasswdClient;
import org.apache.kerby.kerberos.kerb.admin.kpasswd.PasswdConfig;
import org.apache.kerby.kerberos.kerb.admin.kpasswd.PasswdHandler;
import org.apache.kerby.kerberos.kerb.admin.kpasswd.PasswdUtil;
import org.apache.kerby.kerberos.kerb.admin.kpasswd.command.ChangepwCommand;
import org.apache.kerby.kerberos.kerb.admin.kpasswd.command.KpasswdCommand;
import org.apache.kerby.kerberos.kerb.admin.kpasswd.impl.DefaultPasswdHandler;
import org.apache.kerby.kerberos.kerb.admin.kpasswd.request.PasswdRequest;
import org.apache.kerby.kerberos.kerb.ccache.CredentialCache;
import org.apache.kerby.kerberos.kerb.transport.KrbNetwork;
import org.apache.kerby.kerberos.kerb.transport.KrbTransport;
import org.apache.kerby.kerberos.kerb.transport.TransportPair;
import org.apache.kerby.util.OSUtil;

import java.io.File;
import java.io.IOException;
import java.util.Scanner;

/**
 * A running tool for password client.
 */
public class PasswdClientTool {
    private static final String USAGE = (OSUtil.isWindows()
        ? "Usage: bin\\kpasswdClient.cmd" : "Usage: sh bin/kpasswdClient.sh")
        + " <conf-file>\n"
        + "\tExample:\n"
        + "\t\t"
        + (OSUtil.isWindows()
        ? "bin\\kpasswdClient.cmd" : "sh bin/kpasswdClient.sh")
        + " conf\n";

    private static final String LEGAL_COMMANDS = "Available commands are: "
        + "\n"
        + "change_password, changepw\n"
        + "                         Change password\n"
        + "//set_password, setpw\n"
        + "//                         Set password\n";

    public static void main(String[] args) throws KrbException, IOException {

        if (args.length != 1) {
            System.err.println(USAGE);
            System.exit(1);
        }

        String confDirPath = args[0];
        PasswdClient passwdClient = new PasswdClient(new File(confDirPath));
        PasswdConfig passwdConfig = passwdClient.getPasswdConfig();

        passwdClient.setAdminRealm(passwdConfig.getAdminRealm());
        passwdClient.setAllowTcp(true);
        passwdClient.setAllowUdp(true);
        passwdClient.setAdminTcpPort(passwdConfig.getAdminPort());
        passwdClient.setAdminUdpPort(passwdConfig.getAdminPort());

        passwdClient.init();
        System.out.println("password client init successful!");


        System.out.println("enter \"command\" to see legal commands.");

        try (Scanner scanner = new Scanner(System.in, "UTF-8")) {
            String input = scanner.nextLine();

            while (!(input.equals("quit") || input.equals("exit") || input.equals("q"))) {
                execute(passwdClient, input);
                input = scanner.nextLine();
            }
        }
    }

    private static void execute(PasswdClient passwdClient, String input) throws KrbException, IOException {
        input = input.trim();
        if (input.startsWith("command")) {
            System.out.println(LEGAL_COMMANDS);
            return;
        }

        KpasswdCommand executor = null;

        if (input.startsWith("change_password") || input.startsWith("changepw")) {
            executor = new ChangepwCommand(passwdClient);
        } else {
            System.out.println(LEGAL_COMMANDS);
            return;
        }
        executor.execute(input);
    }
}
