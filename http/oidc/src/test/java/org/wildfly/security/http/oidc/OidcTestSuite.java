/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2026 Red Hat, Inc., and individual contributors
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

import org.junit.runner.RunWith;
import org.junit.runners.Suite;

/**
 * Test suite for OIDC tests that share a single Keycloak container instance.
 * This suite optimizes test execution by starting Keycloak once for all included test classes,
 * rather than starting and stopping it for each test class individually.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@RunWith(Suite.class)
@Suite.SuiteClasses({
    OidcTest.class,
    BearerTest.class,
    QueryParamsEnabledTest.class,
    QueryParamsDisabledTest.class,
    MockOidcClientConfiguration.class
})
public class OidcTestSuite extends OidcBaseTest {

    private static final int ACCESS_TOKEN_LIFESPAN = 120;
    private static final int SESSION_MAX_LIFESPAN = 120;
    private static final boolean CONFIGURE_CLIENT_SCOPES = true;
    private static final boolean DIRECT_ACCESS_GRANT_ENABLED = true;
    private static final String BEARER_ONLY_CLIENT_ID = "bearer-client";
    private static final String CORS_CLIENT_ID = "cors-client";


}