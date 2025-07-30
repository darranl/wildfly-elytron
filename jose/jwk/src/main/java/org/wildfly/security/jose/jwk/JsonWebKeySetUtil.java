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

/**
 * Utility methods for JSON Web Key Sets.
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 * @since 1.14.0
 */
public class JsonWebKeySetUtil {

    public static Map<String, PublicKey> getKeysForUse(JsonWebKeySet keySet, JWK.Use requestedUse) {
        Map<String, PublicKey> result = new HashMap<>();
        for (JWK jwk : keySet.getKeys()) {
            if (jwk.getPublicKeyUse().equals(requestedUse.asString()) && isKeyTypeSupported(jwk.getKeyType())) {
                result.put(jwk.getKeyId(), toPublicKey(jwk));
            }
        }
        return result;
    }

}
