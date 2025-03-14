/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.sasl.test;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.wildfly.security.auth.server.MechanismConfigurationSelector;
import org.wildfly.security.sasl.digest.DigestServerFactory;
import org.wildfly.security.sasl.digest.WildFlyElytronSaslDigestProvider;
import org.wildfly.security.sasl.util.SaslMechanismInformation;

import java.security.Provider;
import java.security.Security;

import static org.junit.Assert.fail;

// has dependency on wildfly-elytron-client
public class SaslAvailableRealmsCallbackTest {

    private static final String DIGEST = SaslMechanismInformation.Names.DIGEST_MD5;

    private static final Provider providers = WildFlyElytronSaslDigestProvider.getInstance();

    @BeforeClass
    public static void registerPasswordProvider() {
        Security.addProvider(providers);
    }

    @AfterClass
    public static void removePasswordProvider() {
        Security.removeProvider(providers.getName());
    }

    @Ignore("ELY-1745")
    @Test
    public void testNullMechanismConfigurationSelector() throws Exception {
        // fixme: ELY-1745
        new SaslServerBuilder(DigestServerFactory.class, DIGEST).setMechanismConfigurationSelectorSupplier(() -> null).build();
    }

    @Test
    public void testNullMechanismConfiguration()  {
        try {
            new SaslServerBuilder(DigestServerFactory.class, DIGEST).setDontAssertBuiltServer().setMechanismConfigurationSelectorSupplier(() -> MechanismConfigurationSelector.constantSelector(null)).build();
            fail("Expected exception to be thrown");
        } catch (Throwable t) {
            t.printStackTrace();
        }
    }




}
