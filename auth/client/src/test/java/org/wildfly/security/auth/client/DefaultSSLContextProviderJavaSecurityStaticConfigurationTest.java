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

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Test that default SSLContext from provider can use static java.security file configuration
 */
public class DefaultSSLContextProviderJavaSecurityStaticConfigurationTest {

    // Source test data (immutable) - read from test-classes
    private static final String TEST_RESOURCES_DIR = "./target/test-classes/org/wildfly/security/auth/client/";

    // Test working directory - write outputs here
    private static final String TEST_OUTPUT_DIR = "./target/test-output/auth-client-sslcontext/";

    // Absolute path to working directory (for java.security and config files)
    private static Path TEST_OUTPUT_PATH;

    @BeforeClass
    public static void setupTestEnvironment() throws IOException {
        // 1. Create clean test output directory
        TEST_OUTPUT_PATH = Paths.get(TEST_OUTPUT_DIR).toAbsolutePath().normalize();

        if (TEST_OUTPUT_PATH.toFile().exists()) {
            Files.walk(TEST_OUTPUT_PATH)
                    .sorted(Comparator.reverseOrder())
                    .map(Path::toFile)
                    .forEach(File::delete);
        }
        Files.createDirectories(TEST_OUTPUT_PATH);

        // 2. Copy immutable test resources to working directory
        copyTestResources();

        // 3. Update java.security with absolute paths
        updateJavaSecurityFile();

        // 4. Update wildfly-config.xml with absolute paths
        updateWildFlyConfigFile();
    }

    private static void copyTestResources() throws IOException {
        Path sourceBase = Paths.get(TEST_RESOURCES_DIR);

        // Copy java.security
        Files.copy(
            sourceBase.resolve("java.security"),
            TEST_OUTPUT_PATH.resolve("java.security"),
            StandardCopyOption.REPLACE_EXISTING
        );

        // Copy wildfly-config XML
        Files.copy(
            sourceBase.resolve("test-wildfly-config-client-default-sslcontext.xml"),
            TEST_OUTPUT_PATH.resolve("test-wildfly-config-client-default-sslcontext.xml"),
            StandardCopyOption.REPLACE_EXISTING
        );

        // Copy client.keystore (note: keystore is in parent resources directory)
        Path keystoreSrc = Paths.get("./target/test-classes/client.keystore");
        if (keystoreSrc.toFile().exists()) {
            Files.copy(
                keystoreSrc,
                TEST_OUTPUT_PATH.resolve("client.keystore"),
                StandardCopyOption.REPLACE_EXISTING
            );
        }
    }

    private static void updateJavaSecurityFile() throws IOException {
        Path javaSecurityFile = TEST_OUTPUT_PATH.resolve("java.security");
        List<String> lines = Files.readAllLines(javaSecurityFile);

        // Update provider configuration line with absolute path to wildfly-config.xml
        List<String> updatedLines = lines.stream()
            .map(line -> {
                if (line.startsWith("security.provider.1=org.wildfly.security.auth.client.WildFlyElytronClientDefaultSSLContextProvider")) {
                    // Convert path to proper file:/// URL format (three slashes for absolute paths)
                    String configPath = TEST_OUTPUT_PATH.resolve("test-wildfly-config-client-default-sslcontext.xml")
                        .toAbsolutePath()
                        .toUri()
                        .toString();
                    return "security.provider.1=org.wildfly.security.auth.client.WildFlyElytronClientDefaultSSLContextProvider " + configPath;
                }
                return line;
            })
            .collect(Collectors.toList());

        Files.write(javaSecurityFile, updatedLines);
    }

    private static void updateWildFlyConfigFile() throws IOException {
        Path configFile = TEST_OUTPUT_PATH.resolve("test-wildfly-config-client-default-sslcontext.xml");
        String content = Files.readString(configFile);

        // Update keystore path to absolute path
        String keystorePath = TEST_OUTPUT_PATH.resolve("client.keystore").toAbsolutePath().toString();

        // Replace the keystore file path
        content = content.replace(
            "src/test/resources/client.keystore",
            keystorePath
        );

        // Add trust-store configuration using the same keystore
        // Insert after key-store-ssl-certificate section and before protocol
        if (!content.contains("<trust-store")) {
            content = content.replace(
                "<protocol names=\"TLSv1.3\" />",
                "<trust-store key-store-name=\"keystore1\"/>\n                <protocol names=\"TLSv1.3\" />"
            );
        }

        Files.writeString(configFile, content);
    }

    @Test
    public void testDefaultSSLContextJavaSecurityStaticConfiguration() throws Exception {
        // Get current Java executable
        String javaHome = System.getProperty("java.home");
        String javaBin = javaHome + File.separator + "bin" + File.separator + "java";

        // Build classpath from current test classpath
        String classpath = System.getProperty("java.class.path");

        // Path to java.security file (note the "=" prefix for override mode)
        String javaSecurityPath = "=" + TEST_OUTPUT_PATH.resolve("java.security").toAbsolutePath().toString();

        // Build ProcessBuilder
        ProcessBuilder processBuilder = new ProcessBuilder(
            javaBin,
            "-classpath", classpath,
            "-Djava.security.properties=" + javaSecurityPath,
            "org.wildfly.security.auth.client.DefaultSSLContextProviderTestUtility"
        );

        // Set working directory to match test execution directory
        processBuilder.directory(new File(System.getProperty("user.dir")));

        // Redirect error stream for easier debugging
        processBuilder.redirectErrorStream(false);

        // Start forked JVM process
        Process process = processBuilder.start();

        // Capture stdout and stderr
        StringBuilder stdout = new StringBuilder();
        StringBuilder stderr = new StringBuilder();

        try (BufferedReader stdoutReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
             BufferedReader stderrReader = new BufferedReader(new InputStreamReader(process.getErrorStream()))) {

            String line;
            while ((line = stdoutReader.readLine()) != null) {
                stdout.append(line).append("\n");
            }
            while ((line = stderrReader.readLine()) != null) {
                stderr.append(line).append("\n");
            }
        }

        // Wait for process to complete
        int exitCode = process.waitFor();

        // Assert success
        if (exitCode != 0) {
            Assert.fail("Forked JVM process failed with exit code: " + exitCode + "\n\n" +
                       "=== STDOUT ===\n" + stdout.toString() + "\n" +
                       "=== STDERR ===\n" + stderr.toString());
        }
    }

    @AfterClass
    public static void cleanup() throws Exception {
        // Cleanup test output directory only (not immutable test-classes)
        // This prevents issues when running multiple JDK versions
        if (TEST_OUTPUT_PATH != null && TEST_OUTPUT_PATH.toFile().exists()) {
            Files.walk(TEST_OUTPUT_PATH)
                    .sorted(Comparator.reverseOrder())
                    .map(Path::toFile)
                    .forEach(File::delete);
        }
    }
}
