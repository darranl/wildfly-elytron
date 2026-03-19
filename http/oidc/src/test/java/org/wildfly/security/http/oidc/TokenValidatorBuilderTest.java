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

import org.junit.Assert;
import org.junit.Test;

/**
 * Tests for TokenValidator.
 *
 * @author <a href="mailto:hello@methum.me">Methum Thimbiripola</a>
 */

public class TokenValidatorBuilderTest {


    @Test
    public void testTokenValidatorBuilderWithAllRequiredFields(){

        OidcClientConfiguration clientConfiguration = new OidcClientConfiguration(){

            @Override
            public String getIssuerUrl(){
                return "https://localhost/issuer";
            }

            @Override
            public String getResourceName(){
                return "test-client";
            }

            @Override
            public String getTokenSignatureAlgorithm(){
                return "RS256";
            }

            @Override
            public PublicKeyLocator getPublicKeyLocator(){
                return new JWKPublicKeyLocator();
            }

        };

        TokenValidator tokenValidator = TokenValidator.builder(clientConfiguration).build();
        Assert.assertNotNull(tokenValidator);
    }


    @Test(expected = IllegalArgumentException.class)
    public void testTokenValidatorBuilderWithMissingIssuer(){

        OidcClientConfiguration clientConfiguration = new OidcClientConfiguration(){

            @Override
            public String getIssuerUrl(){
                return null;
            }

            @Override
            public String getResourceName(){
                return "test-client";
            }

            @Override
            public String getTokenSignatureAlgorithm(){
                return "RS256";
            }

            @Override
            public PublicKeyLocator getPublicKeyLocator(){
                return new JWKPublicKeyLocator();
            }

        };

        TokenValidator.builder(clientConfiguration).build();
    }


    @Test(expected = IllegalArgumentException.class)
    public void testTokenValidatorBuilderWithMissingClientId(){

        OidcClientConfiguration clientConfiguration = new OidcClientConfiguration(){

            @Override
            public String getIssuerUrl(){
                return "https://localhost/issuer";
            }

            @Override
            public String getResourceName(){
                return null;
            }

            @Override
            public String getTokenSignatureAlgorithm(){
                return "RS256";
            }

            @Override
            public PublicKeyLocator getPublicKeyLocator(){
                return new JWKPublicKeyLocator();
            }

        };

        TokenValidator.builder(clientConfiguration).build();

    }

    @Test(expected = IllegalArgumentException.class)
    public void testTokenValidatorBuilderWithMissingJwsAlgorithm(){

        OidcClientConfiguration clientConfiguration = new OidcClientConfiguration(){

            @Override
            public String getIssuerUrl(){
                return "https://localhost/issuer";
            }

            @Override
            public String getResourceName(){
                return "test-client";
            }

            @Override
            public String getTokenSignatureAlgorithm(){
                return null;
            }

            @Override
            public PublicKeyLocator getPublicKeyLocator(){
                return new JWKPublicKeyLocator();
            }

        };

       TokenValidator.builder(clientConfiguration).build();

    }


    @Test(expected = IllegalArgumentException.class)
    public void testTokenValidatorBuilderWithMissingPublicKeyAndClientSecretKey(){

        OidcClientConfiguration clientConfiguration = new OidcClientConfiguration(){

            @Override
            public String getIssuerUrl(){
                return "https://localhost/issuer";
            }

            @Override
            public String getResourceName(){
                return "test-client";
            }

            @Override
            public String getTokenSignatureAlgorithm(){
                return "RS256";
            }

            @Override
            public PublicKeyLocator getPublicKeyLocator(){
                return null;
            }

            @Override
            public ClientCredentialsProvider getClientAuthenticator(){
                return null;
            }

        };

        TokenValidator.builder(clientConfiguration).build();

    }

}
