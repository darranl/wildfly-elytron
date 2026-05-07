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

import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertEquals;
import static org.wildfly.security.http.oidc.Oidc.AUTH_SERVER_URL;
import static org.wildfly.security.http.oidc.Oidc.CREDENTIALS;
import static org.wildfly.security.http.oidc.Oidc.PUBLIC_CLIENT;
import static org.wildfly.security.http.oidc.Oidc.REALM;
import static org.wildfly.security.http.oidc.Oidc.RESOURCE;
import static org.wildfly.security.http.oidc.Oidc.SSL_REQUIRED;
/**
 * Unit tests for relative URL resolution in OIDC authentication.
 * These tests do not require Docker containers and test the URL resolution logic directly.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class RelativePathAsAuthServerUrlUnitTest extends OidcBaseTest {
    @Test
    public void testUnitRelativeAuthServerUrlIsResolvedCorrectly() throws Exception {
        OidcClientConfiguration oidcClientConfiguration = OidcClientConfigurationBuilder.build(
            getOidcConfigurationInputStream(CLIENT_SECRET, "/keycloak")
        );
        assertEquals(OidcClientConfiguration.RelativeUrlsUsed.ALWAYS, oidcClientConfiguration.getRelativeUrls());
        OidcClientContext oidcClientContext = new OidcClientContext(oidcClientConfiguration);
        // Test with localhost:1234
        OidcClientConfiguration oidcClientConfigurationWithResolvedUrls = oidcClientContext.resolveUrls(
            oidcClientConfiguration,
            new OidcHttpFacade(
                new TestingHttpServerRequest(null, new URI("http://localhost:1234/keycloak/myTestApp")),
                oidcClientContext,
                null
            )
        );
        // relative URL is taken from HTTP "Host" header of incoming request
        assertEquals("http://localhost:1234/keycloak", oidcClientConfigurationWithResolvedUrls.getAuthServerBaseUrl());
        // Test with test.com:4567
        oidcClientConfigurationWithResolvedUrls = oidcClientContext.resolveUrls(
            oidcClientConfiguration,
            new OidcHttpFacade(
                new TestingHttpServerRequest(null, new URI("http://test.com:4567/keycloak/myTestApp")),
                oidcClientContext,
                null
            )
        );
        // relative URL is taken from HTTP "Host" header of incoming request
        assertEquals("http://test.com:4567/keycloak", oidcClientConfigurationWithResolvedUrls.getAuthServerBaseUrl());
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