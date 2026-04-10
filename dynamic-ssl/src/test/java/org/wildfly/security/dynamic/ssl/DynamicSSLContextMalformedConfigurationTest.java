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

import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.SSLContext;

import org.junit.Assert;
import org.junit.Test;
import org.wildfly.client.config.ConfigXMLParseException;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.ElytronXmlParser;
import org.wildfly.security.auth.client.MatchRule;

/**
 * Negative tests for invalid AuthenticationContext SSL rules used by DynamicSSLContext.
 */
public class DynamicSSLContextMalformedConfigurationTest {

    private static final String DEFAULT_ERROR_CODE = "ELY21009:";
    private static final String DEFAULT_ERROR_FRAGMENT = "default SSLContext";
    private static final String CONFIGURED_ERROR_CODE = "ELY21010:";
    private static final String CONFIGURED_ERROR_FRAGMENT = "all configured SSLContexts";
    private static final String URI_ERROR_CODE = "ELY21011:";
    private static final String URI_ERROR_FRAGMENT = "provided URI";
    private static final String UNKNOWN_SSL_CONTEXT_ERROR =
            "ELY01129: Unknown SSL context \"missing-context\" specified";
    private static final String DUPLICATE_SSL_CONTEXT_ERROR =
            "ELY01130: Duplicate SSL context name \"duplicate-context\"";
    private static final String UNDERLYING_ERROR = "Configured SSLContext creation failed";
    private static final SecurityFactory<SSLContext> FAILING_SSL_CONTEXT_FACTORY =
            () -> {
                throw new NoSuchAlgorithmException(UNDERLYING_ERROR);
            };

    @Test
    public void malformedDefaultConfigurationIsWrappedWhenResolvingDefaultSSLContext() {
        AuthenticationContext authenticationContext = malformedDefaultAuthenticationContext();

        authenticationContext.run(() -> {
            DynamicSSLContextException exception = Assert.assertThrows(DynamicSSLContextException.class,
                    () -> new DynamicSSLContextImpl().getConfiguredDefault());
            assertWrappedFailure(exception, DEFAULT_ERROR_CODE, DEFAULT_ERROR_FRAGMENT);
        });
    }

    @Test
    public void malformedRuleConfigurationIsWrappedWhenResolvingConfiguredSSLContexts() {
        AuthenticationContext authenticationContext = malformedRuleAuthenticationContext();

        authenticationContext.run(() -> {
            DynamicSSLContextException exception = Assert.assertThrows(DynamicSSLContextException.class,
                    () -> new DynamicSSLContextImpl().getConfiguredSSLContexts());
            assertWrappedFailure(exception, CONFIGURED_ERROR_CODE, CONFIGURED_ERROR_FRAGMENT);
        });
    }

    @Test
    public void malformedRuleConfigurationIsWrappedWhenResolvingSSLContextForUri() {
        AuthenticationContext authenticationContext = malformedRuleAuthenticationContext();

        authenticationContext.run(() -> {
            DynamicSSLContextException exception = Assert.assertThrows(DynamicSSLContextException.class,
                    () -> new DynamicSSLContextImpl().getSSLContext(URI.create("https://localhost:12345")));
            assertWrappedFailure(exception, URI_ERROR_CODE, URI_ERROR_FRAGMENT);
        });
    }

    @Test
    public void malformedDefaultConfigurationFailsWhenAuthenticationContextIsPassedExplicitly() {
        NoSuchAlgorithmException exception = Assert.assertThrows(NoSuchAlgorithmException.class,
                () -> new DynamicSSLContextImpl(malformedDefaultAuthenticationContext()));
        Assert.assertEquals(UNDERLYING_ERROR, exception.getMessage());
    }

    @Test
    public void malformedRuleConfigurationFailsWhenAuthenticationContextIsPassedExplicitly() {
        NoSuchAlgorithmException exception = Assert.assertThrows(NoSuchAlgorithmException.class,
                () -> new DynamicSSLContextImpl(malformedRuleAuthenticationContext()));
        Assert.assertEquals(UNDERLYING_ERROR, exception.getMessage());
    }

    @Test
    public void malformedDefaultConfigurationFailsWhenCreatingSocketFactory() {
        AuthenticationContext authenticationContext = malformedDefaultAuthenticationContext();

        authenticationContext.run(() -> {
            IllegalStateException exception = Assert.assertThrows(IllegalStateException.class,
                    () -> newDynamicSSLContext().getSocketFactory());
            Assert.assertEquals("ELY21005: Cannot obtain default SSLContext from DynamicSSLContext implementation", exception.getMessage());
        });
    }

    @Test
    public void malformedRuleConfigurationFailsWhenComputingSupportedCipherSuites() {
        AuthenticationContext authenticationContext = malformedRuleAuthenticationContext();

        authenticationContext.run(() -> {
            SSLContext dynamicSSLContext = newDynamicSSLContext();
            IllegalStateException exception = Assert.assertThrows(IllegalStateException.class,
                    () -> dynamicSSLContext.getSocketFactory().getSupportedCipherSuites());
            Assert.assertEquals("ELY21003: Provider for DynamicSSLContextSPI threw an exception when getting configured SSLContexts",
                    exception.getMessage());
        });
    }

    @Test
    public void malformedRuleConfigurationFailsWhenCreatingSocket() {
        AuthenticationContext authenticationContext = malformedRuleAuthenticationContext();

        authenticationContext.run(() -> {
            SSLContext dynamicSSLContext = newDynamicSSLContext();
            IOException exception = Assert.assertThrows(IOException.class,
                    () -> dynamicSSLContext.getSocketFactory().createSocket("localhost", 12345));
            Assert.assertTrue(exception.getCause() instanceof DynamicSSLContextException);
            assertWrappedFailure((DynamicSSLContextException) exception.getCause(), URI_ERROR_CODE, URI_ERROR_FRAGMENT);
        });
    }

    @Test
    public void malformedRuleConfigurationFailsWhenCreatingEngine() {
        AuthenticationContext authenticationContext = malformedRuleAuthenticationContext();

        authenticationContext.run(() -> {
            IllegalStateException exception = Assert.assertThrows(IllegalStateException.class,
                    () -> newDynamicSSLContext().createSSLEngine("localhost", 12345));
            Assert.assertEquals("ELY21007: Could not create dynamic ssl context engine", exception.getMessage());
        });
    }

    @Test
    public void malformedXmlWithUnknownSslContextReportsParseFailure() {
        ConfigXMLParseException exception = Assert.assertThrows(ConfigXMLParseException.class,
                () -> parseAuthenticationContext("wildfly-config-dynamic-ssl-malformed-unknown-context.xml"));
        assertMessageStartsWith(exception, UNKNOWN_SSL_CONTEXT_ERROR);
    }

    @Test
    public void malformedXmlWithDuplicateSslContextReportsParseFailure() {
        ConfigXMLParseException exception = Assert.assertThrows(ConfigXMLParseException.class,
                () -> parseAuthenticationContext("wildfly-config-dynamic-ssl-malformed-duplicate-context.xml"));
        assertMessageStartsWith(exception, DUPLICATE_SSL_CONTEXT_ERROR);
    }

    private static void assertWrappedFailure(DynamicSSLContextException exception, String expectedCode, String expectedMessageFragment) {
        Assert.assertTrue("Expected error code " + expectedCode + " in message: " + exception.getMessage(),
                exception.getMessage().startsWith(expectedCode));
        Assert.assertTrue("Expected message fragment '" + expectedMessageFragment + "' in message: " + exception.getMessage(),
                exception.getMessage().contains(expectedMessageFragment));
        Assert.assertTrue(exception.getCause() instanceof NoSuchAlgorithmException);
        Assert.assertEquals(UNDERLYING_ERROR, exception.getCause().getMessage());
    }

    private static void assertMessageStartsWith(Exception exception, String expectedPrefix) {
        Assert.assertTrue(exception.getMessage().startsWith(expectedPrefix));
    }

    private DynamicSSLContext newDynamicSSLContext() {
        try {
            return new DynamicSSLContext();
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        }
    }

    private AuthenticationContext malformedDefaultAuthenticationContext() {
        return AuthenticationContext.empty().withSsl(MatchRule.ALL, FAILING_SSL_CONTEXT_FACTORY);
    }

    private AuthenticationContext malformedRuleAuthenticationContext() {
        return AuthenticationContext.empty()
                .withSsl(MatchRule.ALL.matchHost("localhost").matchPort(12345), FAILING_SSL_CONTEXT_FACTORY)
                .withSsl(MatchRule.ALL, SSLContext::getDefault);
    }

    private AuthenticationContext parseAuthenticationContext(String path) throws Exception {
        URL config = getClass().getResource(path);
        return ElytronXmlParser.parseAuthenticationClientConfiguration(config.toURI()).create();
    }
}
