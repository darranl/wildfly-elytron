/*
 * Copyright The WildFly Elytron Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.jose.jwk;

import static org.junit.Assert.assertEquals;
import static org.wildfly.security.jose.jwk.JsonWebKeySetUtil.FOR_SIGNATURE_VALIDATION;
import static org.wildfly.security.jose.jwk.JsonWebKeySetUtil.getKeys;
import static org.wildfly.security.jose.util.JsonSerialization.readValue;
import static org.wildfly.security.realm.token.test.util.JwkTestUtil.createRsaJwk;
import static org.wildfly.security.realm.token.test.util.JwkTestUtil.jwksToJson;

import java.io.IOException;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Map;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.realm.token.test.util.RsaJwk;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonWriter;

/**
 * Test case to test parsing of JSON Web Keys and related handling.
 *
 * This test deliberately uses alternate JWK representations to the runtime
 * implementation so we don't accidentally test our parser works with itself.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class JsonWebKeySetTest {

    private static KeyPairGenerator keyPairGenerator;

    @BeforeClass
    public static void setupKeyPairGenerator() throws NoSuchAlgorithmException {
        keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    }

    @AfterClass
    public static void removeKeyPairGenerator() {
        keyPairGenerator = null;
    }

    @Test
    public void testSingleJWKUse() throws IOException {
        performTest(1,
            createJwk("1", "sig"));
    }

    @Test
    public void testMultipleJWKUse() throws IOException {
        performTest(3,
            createJwk("2", "sig"),
            createJwk("3", "sig"),
            createJwk("4", "enc"),
            createJwk("5", "sig"));
    }

    @Test
    public void testNoJWKUse() throws IOException {
        performTest(0,
            createJwk("5", "enc"),
            createJwk("6", "enc"));
    }

    @Test
    public void testSingleJWKSingleKeyOps() throws IOException {
        performTest(1,
            createJwk("7", null, "verify"));
    }

    @Test
    public void testMultipleJWKSingleKeyOps() throws IOException {
        performTest(3,
            createJwk("8", null, "verify"),
            createJwk("9", null, "verify"),
            createJwk("10", null, "sign"),
            createJwk("11", null, "verify"));
    }

    @Test
    public void testNoJWKSingleKeyOps() throws IOException {
        performTest(0,
            createJwk("12", null, "sign"),
            createJwk("13", null, "encrypt"));
    }

    @Test
    public void testSingleJWKMultipleKeyOps() throws IOException {
        performTest(1,
            createJwk("14", null, "verify", "sign"));
    }

    @Test
    public void testMultipleJWKMultipleKeyOps() throws IOException {
        performTest(3,
            createJwk("15", null, "verify", "sign"),
            createJwk("16", null, "verify", "encrypt"),
            createJwk("17", null, "sign", "encrypt"),
            createJwk("18", null, "verify", "decrypt"));
    }

    @Test
    public void testNoJWKMultipleKeyOps() throws IOException {
        performTest(0,
            createJwk("19", null, "decrypt", "encrypt"),
            createJwk("20", null, "sign", "decrypt"));
    }

    @Test
    public void testMultipleJWKMixedSingleKeyOps() throws IOException {
        performTest(2,
            createJwk("21", "sig"),
            createJwk("22", "enc"),
            createJwk("23", null, "verify"),
            createJwk("24", null, "encrypt"));
    }

    @Test
    public void testMultipleJWKMixedMultipleKeyOps() throws IOException {
        performTest(2,
            createJwk("25", "sig"),
            createJwk("26", "enc"),
            createJwk("27", null, "verify", "sign"),
            createJwk("28", null, "encrypt", "decrypt"));
    }

    private void performTest(final int expectedPublicKeyCount, final RsaJwk... jwks) throws IOException {
        JsonObject jwksJson = jwksToJson(jwks);

        StringWriter stringWriter = new StringWriter();
        JsonWriter jsonWriter = Json.createWriter(stringWriter);
        jsonWriter.write(jwksJson);
        jsonWriter.close();

        String jsonData = stringWriter.toString();

        JsonWebKeySet jsonWebKeySet = readValue(jsonData, JsonWebKeySet.class);

        Map<String, PublicKey> publicKeyMap = getKeys(jsonWebKeySet, FOR_SIGNATURE_VALIDATION);

        assertEquals("Expected PublicKey count", expectedPublicKeyCount, publicKeyMap.size());
    }

    private RsaJwk createJwk(final String kid, final String use, final String... keyOps) {
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        RsaJwk rsaJwk = createRsaJwk(keyPair, kid);
        if (use != null) {
            rsaJwk.setUse(use);
        } else if (keyOps.length > 0) {
            rsaJwk.setKeyOps(keyOps);
        }

        return rsaJwk;
    }
}
