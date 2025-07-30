/*
 * Copyright The WildFly Elytron Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.realm.token.test.util;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;

import jakarta.json.Json;
import jakarta.json.JsonArrayBuilder;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;

/**
 * Base utility class for working with JSON Web Keys.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class JwkTestUtil {

    public static JsonObject jwksToJson(RsaJwk... jwks) {
        JsonArrayBuilder jab = Json.createArrayBuilder();
        for (int i = 0; i < jwks.length; i++){
            JsonObjectBuilder jwk = Json.createObjectBuilder()
                    .add("kty", jwks[i].getKty())
                    .add("alg", jwks[i].getAlg())
                    .add("kid", jwks[i].getKid())
                    .add("n", jwks[i].getN())
                    .add("e", jwks[i].getE());
            if (jwks[i].getUse() != null) {
                jwk.add("use", jwks[i].getUse());
            } else if (jwks[i].getKeyOps() != null) {
                JsonArrayBuilder keyOpBuilder = Json.createArrayBuilder();
                for (String keyOp : jwks[i].getKeyOps()) {
                    keyOpBuilder.add(keyOp);
                }
                jwk.add("key_ops", keyOpBuilder);
            }
            jab.add(jwk);
        }
        return Json.createObjectBuilder().add("keys", jab).build();
    }

        public static RsaJwk createRsaJwk(KeyPair keyPair, String kid) {
        RSAPublicKey pk = (RSAPublicKey) keyPair.getPublic();
        RsaJwk jwk = new RsaJwk();

        jwk.setAlg("RS256");
        jwk.setKid(kid);
        jwk.setKty("RSA");
        jwk.setE(Base64.getUrlEncoder().withoutPadding().encodeToString(toBase64urlUInt(pk.getPublicExponent())));
        jwk.setN(Base64.getUrlEncoder().withoutPadding().encodeToString(toBase64urlUInt(pk.getModulus())));

        return jwk;
    }

    // rfc7518 dictates the use of Base64urlUInt for "n" and "e" and it explicitly mentions that the
    // minimum number of octets should be used and the 0 leading sign byte should not be included
    private static byte[] toBase64urlUInt(final BigInteger bigInt) {
        byte[] bytes = bigInt.toByteArray();
        int i = 0;
        while (i < bytes.length && bytes[i] == 0) {
            i++;
        }
        if (i > 0 && i < bytes.length) {
            return Arrays.copyOfRange(bytes, i, bytes.length);
        } else {
            return bytes;
        }
    }

}
