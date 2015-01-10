package org.apache.haox.event.network;

import junit.framework.Assert;
import org.apache.haox.event.EventHandler;
import org.apache.haox.event.EventHub;
import org.apache.haox.transport.MessageHandler;
import org.apache.haox.transport.Network;
import org.apache.haox.transport.event.MessageEvent;
import org.apache.haox.transport.event.TransportEventType;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SocketChannel;

public class TestNetworkServer extends TestNetworkBase {

    private EventHub eventHub;

    @Before
    public void setUp() throws IOException {
        setUpServer();
    }

    private void setUpServer() throws IOException {
        eventHub = new EventHub();

        EventHandler messageHandler = new MessageHandler() {
            @Override
            protected void handleMessage(MessageEvent msgEvent) {
                if (msgEvent.getEventType() == TransportEventType.INBOUND_MESSAGE) {
                    msgEvent.getTransport().sendMessage(msgEvent.getMessage());
                }
            }
        };
        eventHub.register(messageHandler);

        Network network = new Network();
        network.setStreamingDecoder(createStreamingDecoder());
        eventHub.register(network);

        eventHub.start();
        network.tcpListen(serverHost, tcpPort);
        network.udpListen(serverHost, udpPort);
    }

    @Test
    public void testNetworkServer() throws IOException, InterruptedException {
        testTcpTransport();
        testUdpTransport();
    }

    private void testTcpTransport() throws IOException, InterruptedException {
        Thread.sleep(10);

        SocketChannel socketChannel = SocketChannel.open();
        socketChannel.configureBlocking(true);
        SocketAddress sa = new InetSocketAddress(serverHost, tcpPort);
        socketChannel.connect(sa);
        socketChannel.write(ByteBuffer.wrap(TEST_MESSAGE.getBytes()));
        ByteBuffer byteBuffer = ByteBuffer.allocate(65536);
        socketChannel.read(byteBuffer);
        byteBuffer.flip();
        clientRecvedMessage = recvBuffer2String(byteBuffer);
        Assert.assertEquals(TEST_MESSAGE, clientRecvedMessage);
    }

    private void testUdpTransport() throws IOException, InterruptedException {
        Thread.sleep(10);

        DatagramChannel socketChannel = DatagramChannel.open();
        socketChannel.configureBlocking(true);
        SocketAddress sa = new InetSocketAddress(serverHost, udpPort);
        socketChannel.send(ByteBuffer.wrap(TEST_MESSAGE.getBytes()), sa);
        ByteBuffer byteBuffer = ByteBuffer.allocate(65536);
        socketChannel.receive(byteBuffer);
        byteBuffer.flip();
        clientRecvedMessage = recvBuffer2String(byteBuffer);
        Assert.assertEquals(TEST_MESSAGE, clientRecvedMessage);
    }

    @After
    public void cleanup() {
        eventHub.stop();
    }
}
