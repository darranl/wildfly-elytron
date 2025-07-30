/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2020 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.jose.jwk;

import static org.wildfly.security.jose.jwk.JWKParser.isKeyTypeSupported;
import static org.wildfly.security.jose.jwk.JWKParser.toPublicKey;

import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Predicate;

/**
 * Utility methods for JSON Web Key Sets.
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 * @since 1.14.0
 */
public class JsonWebKeySetUtil {

    public static Map<String, PublicKey> getKeys(JsonWebKeySet keySet, Predicate<JWK> keyPredicate) {
        Map<String, PublicKey> result = new HashMap<>();
        for (JWK jwk : keySet.getKeys()) {
            if (keyPredicate.test(jwk)) {
                result.put(jwk.getKeyId(), toPublicKey(jwk));
            }
        }
        return result;
    }

    /*
     * Key Filtering Predicates.
     */

    public static Predicate<JWK> SUPPORTED_KEY_TYPE = j -> isKeyTypeSupported(j.getKeyType());

    public static Predicate<JWK> usePredicate(JWK.Use requestedUse) {
        return j -> j.getPublicKeyUse() != null && j.getPublicKeyUse().equals(requestedUse.asString());
    }

    public static Predicate<JWK> keyOpsPredicate(JWK.KeyOp requestedKeyOp) {
        return j -> {
            String[] keyOps = j.getKeyOps();
            if (keyOps != null) {
                for (String keyOp : keyOps) {
                    if (keyOp.equals(requestedKeyOp.asString())) {
                        return true;
                    }
                }
            }

            return false;
        };
    }

    public static Predicate<JWK> FOR_SIGNATURE_VALIDATION = SUPPORTED_KEY_TYPE.and(
        usePredicate(JWK.Use.SIG).or(keyOpsPredicate(JWK.KeyOp.VERIFY)));

    public static Predicate<JWK> FOR_ENCRYPTION = SUPPORTED_KEY_TYPE.and(
        usePredicate(JWK.Use.ENC).or(keyOpsPredicate(JWK.KeyOp.ENCRYPT)));
}
