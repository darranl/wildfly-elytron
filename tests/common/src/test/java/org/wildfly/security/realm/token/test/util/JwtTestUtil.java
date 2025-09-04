/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.realm.token.test.util;

import java.net.URI;
import java.security.KeyPair;
import java.security.PrivateKey;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSASigner;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import jakarta.json.JsonValue;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.RecordedRequest;

/**
 * A utility class containing common methods for working with token realms.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public final class JwtTestUtil extends JwkTestUtil {

    public static String createJwt(KeyPair keyPair, int expirationOffset, int notBeforeOffset) throws Exception {
        return createJwt(keyPair, expirationOffset, notBeforeOffset, null, null);
    }

    public static String createJwt(KeyPair keyPair, int expirationOffset) throws Exception {
        return createJwt(keyPair, expirationOffset, -1);
    }

    public static String createJwt(KeyPair keyPair, int expirationOffset, int notBeforeOffset, String kid, URI jku) throws Exception {
        PrivateKey privateKey = keyPair.getPrivate();
        JWSSigner signer = new RSASSASigner(privateKey);
        JsonObjectBuilder claimsBuilder = createClaims(expirationOffset, notBeforeOffset);

        JWSHeader.Builder headerBuilder = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(new JOSEObjectType("jwt"));

        if (jku != null) {
            headerBuilder.jwkURL(jku);
        }
        if (kid != null) {
            headerBuilder.keyID(kid);
        }

        JWSObject jwsObject = new JWSObject(headerBuilder.build(), new Payload(claimsBuilder.build().toString()));

        jwsObject.sign(signer);

        return jwsObject.serialize();
    }

    public static String createJwt(KeyPair keyPair) throws Exception {
        return createJwt(keyPair, 60);
    }

    public static JsonObjectBuilder createClaims(int expirationOffset, int notBeforeOffset) {
        return createClaims(expirationOffset, notBeforeOffset, null);
    }
    public static JsonObjectBuilder createClaims(int expirationOffset, int notBeforeOffset, JsonObject additionalClaims) {
        JsonObjectBuilder claimsBuilder = Json.createObjectBuilder()
                .add("active", true)
                .add("sub", "elytron@jboss.org")
                .add("iss", "elytron-oauth2-realm")
                .add("aud", Json.createArrayBuilder().add("my-app-valid").add("third-app-valid").add("another-app-valid").build())
                .add("exp", (System.currentTimeMillis() / 1000) + expirationOffset);

        if (additionalClaims != null) {
            for(String name : additionalClaims.keySet()) {
                JsonValue value = additionalClaims.get(name);
                claimsBuilder.add(name, value);
            }
        }
        if (notBeforeOffset > 0) {
            claimsBuilder.add("nbf", (System.currentTimeMillis() / 1000) + notBeforeOffset);
        }

        return claimsBuilder;
    }

    public static Dispatcher createTokenDispatcher(String response) {
        return new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest recordedRequest) {
                return new MockResponse().setBody(response);
            }
        };
    }

}
