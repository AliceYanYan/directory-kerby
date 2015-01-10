package org.apache.kerberos.kerb.server;

import org.apache.kerberos.kerb.client.KrbClient;
import org.apache.kerberos.kerb.server.TestKdcServer;
import org.junit.After;
import org.junit.Before;

public abstract class KdcTestBase {

    protected String kdcRealm;
    protected String clientPrincipal;
    protected String serverPrincipal;

    protected String hostname = "localhost";
    protected short port = 8088;

    protected TestKdcServer kdcServer;
    protected KrbClient krbClnt;

    @Before
    public void setUp() throws Exception {
        setUpKdcServer();
        setUpClient();
    }

    protected void setUpKdcServer() throws Exception {
        kdcServer = new TestKdcServer();
        kdcServer.setKdcHost(hostname);
        kdcServer.setKdcPort(port);
        kdcServer.init();

        kdcRealm = kdcServer.getKdcRealm();
        clientPrincipal = "drankye@" + kdcRealm;

        serverPrincipal = "test-service/localhost@" + kdcRealm;
        kdcServer.createPrincipals(serverPrincipal);
    }

    protected void setUpClient() throws Exception {
        krbClnt = new KrbClient(hostname, port);
        krbClnt.setTimeout(5);
        krbClnt.setKdcRealm(kdcServer.getKdcRealm());
    }

    @After
    public void tearDown() throws Exception {
        kdcServer.stop();
    }
}