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

import static org.junit.Assume.assumeTrue;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import org.junit.AfterClass;
import org.junit.BeforeClass;

/**
 * Tests for the {@code wildfly.elytron.oidc.allow.query.params} system property.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class QueryParamsBaseTest extends OidcBaseTest {

    public static final String QUERY_PARAMS_TEST_REALM = "WildFlyQueryParams";

    @BeforeClass
    public static void startTestContainers() throws Exception {
        assumeTrue("Docker isn't available, OIDC tests will be skipped", isDockerAvailable());
        acquireSharedFixture();
        ensureRealmCreated(KeycloakConfiguration.getRealmRepresentation(QUERY_PARAMS_TEST_REALM, CLIENT_ID, CLIENT_SECRET, CLIENT_HOST_NAME, CLIENT_PORT, CLIENT_APP, 3, 3, false, true));
    }

    @AfterClass
    public static void generalCleanup() throws Exception {
        releaseSharedFixture();
    }

    @Override
    protected InputStream getOidcConfigurationInputStreamWithProviderUrl() {
        String oidcConfig = "{\n" +
                "    \"" + Oidc.RESOURCE + "\" : \"" + CLIENT_ID + "\",\n" +
                "    \"" + Oidc.PUBLIC_CLIENT + "\" : \"false\",\n" +
                "    \"" + Oidc.PROVIDER_URL + "\" : \"" + KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/" + QUERY_PARAMS_TEST_REALM + "\",\n" +
                "    \"" + Oidc.SSL_REQUIRED + "\" : \"EXTERNAL\",\n" +
                "    \"" + Oidc.CREDENTIALS + "\" : {\n" +
                "        \"" + Oidc.ClientCredentialsProviderType.SECRET.getValue() + "\" : \"" + CLIENT_SECRET + "\"\n" +
                "    }\n" +
                "}";
        return new ByteArrayInputStream(oidcConfig.getBytes(StandardCharsets.UTF_8));
    }

}
