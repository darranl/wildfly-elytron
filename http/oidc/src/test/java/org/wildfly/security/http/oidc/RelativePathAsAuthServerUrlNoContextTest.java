/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2024 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.wildfly.security.http.oidc;

import io.restassured.RestAssured;
import okhttp3.mockwebserver.MockWebServer;
import org.apache.http.HttpStatus;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.LoggerFactory;
import org.testcontainers.Testcontainers;
import org.testcontainers.containers.BindMode;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.NginxContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.utility.DockerImageName;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assume.assumeTrue;
import static org.wildfly.common.Assert.assertNotNull;
import static org.wildfly.security.http.oidc.Oidc.AUTH_SERVER_URL;
import static org.wildfly.security.http.oidc.Oidc.CREDENTIALS;
import static org.wildfly.security.http.oidc.Oidc.PUBLIC_CLIENT;
import static org.wildfly.security.http.oidc.Oidc.REALM;
import static org.wildfly.security.http.oidc.Oidc.RESOURCE;
import static org.wildfly.security.http.oidc.Oidc.SSL_REQUIRED;

/**
 * Tests for relative URL in auth-server-url parameter without Keycloak context path.
 * Uses nginx proxy with Testcontainers network aliases to properly test relative URL resolution.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class RelativePathAsAuthServerUrlNoContextTest extends OidcBaseTest {

    private static final String NGINX_IMAGE = "nginx:1.20";
    private static final int PROXY_PORT = 8060;
    private static Network network = null;
    private static NginxContainer<?> nginxContainer;
    private static URL proxyHttpUrl;

    @BeforeClass
    public static void startTestContainers() throws Exception {
        assumeTrue("Docker isn't available, OIDC tests will be skipped", isDockerAvailable());
        System.setProperty("TESTCONTAINERS_HOST_OVERRIDE", "localhost");
        Testcontainers.exposeHostPorts(CLIENT_PORT);

        // Create network
        network = Network.newNetwork();

        // Start MockWebServer (client app)
        if (client == null) {
            client = new MockWebServer();
            client.start(CLIENT_PORT);
        }

        // Start Keycloak without context path
        if (KEYCLOAK_CONTAINER == null) {
            KEYCLOAK_CONTAINER = new KeycloakContainer()
                    .withNetwork(network)
                    .withNetworkAliases("keycloak")
                    .withAccessToHost(true);
            KEYCLOAK_CONTAINER.start();
        }

        // Start nginx proxy
        Slf4jLogConsumer logConsumer = new Slf4jLogConsumer(LoggerFactory.getLogger(RelativePathAsAuthServerUrlNoContextTest.class));
        List<String> portBindings = new ArrayList<>();
        portBindings.add(PROXY_PORT + ":80");

        nginxContainer = new NginxContainer<>(DockerImageName.parse(NGINX_IMAGE))
                .withNetwork(network)
                .withEnv("KC_ENDPOINT", "http://keycloak:8080/realms/WildFly/")
                .withEnv("PROXY_PORT", String.valueOf(PROXY_PORT))
                .withEnv("CLIENT_PORT", String.valueOf(CLIENT_PORT))
                .withExposedPorts(80)
                .withClasspathResourceMapping("org/wildfly/security/http/oidc/nginx.conf", "/etc/nginx/templates/default.conf.template", BindMode.READ_WRITE)
                .withAccessToHost(true);
        nginxContainer.setPortBindings(portBindings);
        nginxContainer.start();
        nginxContainer.followOutput(logConsumer);
        proxyHttpUrl = nginxContainer.getBaseUrl("http", 80);
        assertNotNull(proxyHttpUrl);

        // Create realm
        sendRealmCreationRequest(KeycloakConfiguration.getRealmRepresentation(
                TEST_REALM, CLIENT_ID, CLIENT_SECRET,
                CLIENT_HOST_NAME, CLIENT_PORT, CLIENT_APP,
                false, true
        ));
    }

    @AfterClass
    public static void cleanup() throws Exception {
        // Delete realm
        if (KEYCLOAK_CONTAINER != null && KEYCLOAK_CONTAINER.isRunning()) {
            RestAssured
                    .given()
                    .auth().oauth2(KeycloakConfiguration.getAdminAccessToken(KEYCLOAK_CONTAINER.getAuthServerUrl()))
                    .when()
                    .delete(KEYCLOAK_CONTAINER.getAuthServerUrl() + "/admin/realms/" + TEST_REALM)
                    .then()
                    .statusCode(204);
        }

        // Stop nginx
        if (nginxContainer != null) {
            nginxContainer.stop();
            nginxContainer = null;
        }

        // Stop client
        if (client != null) {
            client.shutdown();
            client = null;
        }

        // Stop Keycloak
        if (KEYCLOAK_CONTAINER != null) {
            KEYCLOAK_CONTAINER.stop();
            KEYCLOAK_CONTAINER = null;
        }

        // Close network
        if (network != null) {
            network.close();
            network = null;
        }

        System.clearProperty("TESTCONTAINERS_HOST_OVERRIDE");
    }

    @Test
    public void testSuccessfulAuthenticationWithRelativeAuthServerUrl() throws Exception {
        performAuthentication(
                getOidcConfigurationInputStream(CLIENT_SECRET, "/"),
                KeycloakConfiguration.ALICE,
                KeycloakConfiguration.ALICE_PASSWORD,
                true,
                HttpStatus.SC_MOVED_TEMPORARILY,
                true,
                proxyHttpUrl + "/" + CLIENT_APP,
                proxyHttpUrl + "/" + CLIENT_APP,
                CLIENT_PAGE_TEXT
        );
    }

    @Test
    public void testWrongRelativeAuthServerUrl() throws Exception {
        performAuthentication(
                getOidcConfigurationInputStream(CLIENT_SECRET, "/wrong_relative_url_endpoint"),
                KeycloakConfiguration.ALICE,
                KeycloakConfiguration.ALICE_PASSWORD,
                true,
                -1,
                proxyHttpUrl + "/" + CLIENT_APP,
                null,
                null,
                null,
                false,
                false,
                true,
                false
        );
    }

    private InputStream getOidcConfigurationInputStream(String clientSecret, String authServerUrl) {
        String oidcConfig = "{\n" +
                "    \"" + REALM + "\" : \"" + TEST_REALM + "\",\n" +
                "    \"" + RESOURCE + "\" : \"" + CLIENT_ID + "\",\n" +
                "    \"" + PUBLIC_CLIENT + "\" : \"false\",\n" +
                "    \"" + AUTH_SERVER_URL + "\" : \"" + authServerUrl + "\",\n" +
                "    \"" + SSL_REQUIRED + "\" : \"EXTERNAL\",\n" +
                "    \"" + CREDENTIALS + "\" : {\n" +
                "        \"" + Oidc.ClientCredentialsProviderType.SECRET.getValue() + "\" : \"" + clientSecret + "\"\n" +
                "    }\n" +
                "}";
        return new ByteArrayInputStream(oidcConfig.getBytes(StandardCharsets.UTF_8));
    }
}
