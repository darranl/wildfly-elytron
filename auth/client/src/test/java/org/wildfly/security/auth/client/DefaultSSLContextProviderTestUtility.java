/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2022 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth.client;

import javax.net.ssl.SSLContext;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;

/**
 * Utility class to test default SSLContext provider in a forked JVM process.
 * This allows proper setup of java.security.properties and classpath.
 */
public class DefaultSSLContextProviderTestUtility {

    public static void main(String[] args) {
        System.out.println("=== DefaultSSLContextProviderTestUtility Starting ===");
        System.out.println("Java Version: " + System.getProperty("java.version"));
        System.out.println("Java Home: " + System.getProperty("java.home"));
        System.out.println("Java Security Properties: " + System.getProperty("java.security.properties"));
        System.out.println();

        int exitCode = 0;
        try {
            // Step 1: Check if provider is registered
            System.out.println("Step 1: Checking if WildFlyElytronClientDefaultSSLContextProvider is registered...");
            Provider provider = Security.getProvider("WildFlyElytronClientDefaultSSLContextProvider");
            if (provider == null) {
                System.err.println("ERROR: Provider 'WildFlyElytronClientDefaultSSLContextProvider' is NOT registered!");
                System.err.println("Available providers:");
                for (Provider p : Security.getProviders()) {
                    System.err.println("  - " + p.getName() + " (" + p.getClass().getName() + ")");
                }
                exitCode = 1;
            } else {
                System.out.println("SUCCESS: Provider found: " + provider.getName());
                System.out.println("  Provider class: " + provider.getClass().getName());
                System.out.println("  Provider info: " + provider.getInfo());
            }
            System.out.println();

            // Step 2: Get default SSLContext
            System.out.println("Step 2: Getting default SSLContext...");
            SSLContext defaultSSLContext = null;
            try {
                // Run within empty AuthenticationContext to ensure provider is used
                defaultSSLContext = AuthenticationContext.empty().run((java.security.PrivilegedExceptionAction<SSLContext>) () -> {
                    return SSLContext.getDefault();
                });
                System.out.println("SUCCESS: Default SSLContext obtained");
            } catch (Exception e) {
                System.err.println("ERROR: Failed to get default SSLContext: " + e.getMessage());
                e.printStackTrace(System.err);
                exitCode = 2;
            }
            System.out.println();

            if (defaultSSLContext != null) {
                // Step 3: Verify provider
                System.out.println("Step 3: Verifying SSLContext provider...");
                Provider sslProvider = defaultSSLContext.getProvider();
                System.out.println("SSLContext provider name: " + sslProvider.getName());
                System.out.println("SSLContext provider class: " + sslProvider.getClass().getName());

                if (!WildFlyElytronClientDefaultSSLContextProvider.class.getSimpleName().equals(sslProvider.getName())) {
                    System.err.println("ERROR: Expected provider '" + WildFlyElytronClientDefaultSSLContextProvider.class.getSimpleName()
                        + "' but got '" + sslProvider.getName() + "'");
                    exitCode = 3;
                } else {
                    System.out.println("SUCCESS: Correct provider is being used");
                }
                System.out.println();

                // Step 4: Verify socket factory
                System.out.println("Step 4: Verifying socket factory...");
                if (defaultSSLContext.getSocketFactory() == null) {
                    System.err.println("ERROR: Socket factory is null!");
                    exitCode = 4;
                } else {
                    System.out.println("SUCCESS: Socket factory is available");
                    System.out.println("  Socket factory class: " + defaultSSLContext.getSocketFactory().getClass().getName());
                }
                System.out.println();

                // Step 5: Verify protocols
                System.out.println("Step 5: Verifying SSL protocols...");
                try {
                    String[] protocols = defaultSSLContext.createSSLEngine().getSSLParameters().getProtocols();
                    System.out.println("Enabled protocols: " + Arrays.toString(protocols));
                    System.out.println("Protocol count: " + protocols.length);

                    if (protocols.length != 1) {
                        System.err.println("ERROR: Expected 1 protocol (TLSv1.3) but got " + protocols.length);
                        exitCode = 5;
                    } else if (!"TLSv1.3".equals(protocols[0])) {
                        System.err.println("ERROR: Expected protocol 'TLSv1.3' but got '" + protocols[0] + "'");
                        exitCode = 5;
                    } else {
                        System.out.println("SUCCESS: Correct protocol configuration (TLSv1.3)");
                    }
                } catch (Exception e) {
                    System.err.println("ERROR: Failed to get SSL protocols: " + e.getMessage());
                    e.printStackTrace(System.err);
                    exitCode = 6;
                }
                System.out.println();
            }

            // Final result
            if (exitCode == 0) {
                System.out.println("=== ALL TESTS PASSED ===");
            } else {
                System.err.println("=== TESTS FAILED (exit code: " + exitCode + ") ===");
            }

        } catch (Exception e) {
            System.err.println("FATAL ERROR: Unexpected exception during test execution");
            e.printStackTrace(System.err);
            exitCode = 99;
        }

        System.exit(exitCode);
    }
}
