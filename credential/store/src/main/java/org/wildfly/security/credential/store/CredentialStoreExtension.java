/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.credential.store;

/**
 * A Credential Store implementation may support one or more extension types that expose store-specific methods beyond
 * the standard {@link CredentialStore} API. Callers can use {@link CredentialStore#getSupportedExtensionTypes()} to discover
 * supported types and {@link CredentialStore#getExtensionInstance(Class)} to obtain an implementation.
 * Credential Stores that do not support extensions return an empty list from the {@code getSupportedExtensionTypes}.
 */
public interface CredentialStoreExtension {
}
