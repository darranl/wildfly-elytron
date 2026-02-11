/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2024 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.dynamic.ssl;

import okhttp3.TlsVersion;
import org.junit.Assert;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.BufferedReader;
import java.io.Closeable;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Utility class for running SSLServerSocket instance for testing.
 *
 * @author <a href="mailto:dvilkola@redhat.com">Diana Krepinska (Vilkolakova)</a>
 */
public class SSLServerSocketTestInstance {

    private int port;
    private String keystorePath;
    private String truststorePath;
    private String[] configuredEnabledCipherSuites;
    private SSLServerSocket sslServerSocket;
    private AtomicBoolean running = new AtomicBoolean(false);
    private Thread serverThread;

    public SSLServerSocketTestInstance(String pathToKeystore, String pathToTruststore, int port) {
        this.keystorePath = pathToKeystore;
        this.truststorePath = pathToTruststore;
        this.port = port;
    }

    void setConfiguredEnabledCipherSuites(String[] configuredEnabledCipherSuite) {
        this.configuredEnabledCipherSuites = configuredEnabledCipherSuite;
    }

    public void run() {
        String password = "Elytron";
        SSLContext sslContext = DynamicSSLTestUtils.createSSLContext(this.keystorePath, this.truststorePath, password);
        try {
            SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();
            sslServerSocket = (javax.net.ssl.SSLServerSocket) sslServerSocketFactory.createServerSocket();
            sslServerSocket.setNeedClientAuth(true);
            sslServerSocket.setUseClientMode(false);
            sslServerSocket.setWantClientAuth(true);
            sslServerSocket.setEnabledProtocols(new String[]{
                    TlsVersion.TLS_1_2.javaName(),
                    TlsVersion.TLS_1_3.javaName()
            });
            if (configuredEnabledCipherSuites != null) {
                sslServerSocket.setEnabledCipherSuites(configuredEnabledCipherSuites);
            }
            sslServerSocket.bind(new InetSocketAddress("localhost", port));
            sslServerSocket.setSoTimeout(100);
            serverThread = new Thread(() -> {
                running.set(true);
                while (running.get() && !Thread.currentThread().isInterrupted()) {
                    SSLSocket sslSocket;
                    try {
                        sslSocket = (SSLSocket) sslServerSocket.accept();
                        new Thread(new ServerThread(sslSocket)).start();
                    } catch (java.net.SocketTimeoutException e) {
                        // Expected timeout
                    } catch (Exception e) {
                        if (!running.get() || Thread.currentThread().isInterrupted()) {
                            break;
                        } else {
                            Assert.fail();
                        }
                    }
                }
            });
            serverThread.start();
        } catch (Exception ex) {
            running.set(false);
            Assert.fail();
        }
    }

    public void stop() {
        running.set(false);
        closeQuietly(sslServerSocket);
        if (serverThread != null) {
            serverThread.interrupt();
            try {
                serverThread.join(5000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private static void closeQuietly(Closeable closeable) {
        if (closeable != null) {
            try {
                closeable.close();
            } catch (Exception e) {
                // Ignore exceptions during shutdown
            }
        }
    }

    // Thread handling the socket from client
    public static class ServerThread implements Runnable {
        public static final String STATUS_OK = "HTTP/1.1 200 OK";
        private SSLSocket sslSocket;
        AtomicBoolean running = new AtomicBoolean(false);

        ServerThread(SSLSocket sslSocket) {
            this.sslSocket = sslSocket;
        }

        public void run() {
            try {
                // wait for client's message first so that the first client message will trigger handshake.
                // This way client can set its preferences in SSLParams after creation of bound createSocket(host,port) without server triggering handshake before.
                running.set(true);
                sslSocket.setSoTimeout(10000);
                sslSocket.startHandshake();
                InputStream inputStream = sslSocket.getInputStream();
                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
                while (running.get()) {
                    String line = bufferedReader.readLine();
                    if (line != null && line.equals("Client Hello")) {
                        break;
                    }
                }
                // if successful return 200
                PrintWriter printWriter = new PrintWriter(new OutputStreamWriter(sslSocket.getOutputStream()));
                printWriter.println(STATUS_OK);
                printWriter.flush();
            } catch (Exception ex) {
                if (!sslSocket.isClosed() && running.get()) {
                    ex.printStackTrace();
                    Assert.fail();
                }
            } finally {
                running.set(false);
                SSLServerSocketTestInstance.closeQuietly(sslSocket);
            }
        }
    }
}
