/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.http.cert;

import static org.wildfly.security.http.HttpConstants.CLIENT_CERT_NAME;
import static org.wildfly.security.mechanism._private.ElytronMessages.httpClientCert;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BooleanSupplier;
import java.util.function.Function;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.wildfly.security.auth.callback.AuthenticationCompleteCallback;
import org.wildfly.security.auth.callback.CachedIdentityAuthorizeCallback;
import org.wildfly.security.auth.callback.EvidenceDecodePrincipalCallback;
import org.wildfly.security.auth.callback.EvidenceVerifyCallback;
import org.wildfly.security.auth.callback.PrincipalAuthorizeCallback;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.cache.CachedIdentity;
import org.wildfly.security.cache.IdentityCache;
import org.wildfly.security.evidence.X509PeerCertificateChainEvidence;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpScope;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerRequest;
import org.wildfly.security.http.Scope;
import org.wildfly.security.mechanism.AuthenticationMechanismException;
import org.wildfly.security.mechanism._private.MechanismUtil;
import org.wildfly.security.x500.X500;

/**
 * The CLIENT_CERT authentication mechanism.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
final class ClientCertAuthenticationMechanism implements HttpServerAuthenticationMechanism {

    private static final String IDENTITY_CACHE_KEY = "org.wildfly.elytron.identity-cache";
    private static final String IDENTITY_CACHE_CERTS_KEY = "org.wildfly.elytron.identity-cache-certs";

    private final CallbackHandler callbackHandler;
    private final boolean skipVerification;

    /**
     * Construct a new instance of the {@code ClientCertAuthenticationMechanism} mechanism.
     *
     * @param callbackHandler the {@link CallbackHandler} to use to verify the supplied credentials and to notify to establish the current identity.
     * @param skipVerification whether the certificate verification using {@link EvidenceVerifyCallback} should be skipped
     */
    ClientCertAuthenticationMechanism(CallbackHandler callbackHandler, boolean skipVerification) {
        this.callbackHandler = callbackHandler;
        this.skipVerification = skipVerification;
    }

    /**
     * @see org.wildfly.security.http.HttpServerAuthenticationMechanism#getMechanismName()
     */
    @Override
    public String getMechanismName() {
        return CLIENT_CERT_NAME;
    }

    /**
     * @see org.wildfly.security.http.HttpServerAuthenticationMechanism#evaluateRequest(org.wildfly.security.http.HttpServerRequest)
     */
    @Override
    public void evaluateRequest(HttpServerRequest request) throws HttpAuthenticationException {
        Function<SecurityDomain, IdentityCache> cacheFunction = createIdentityCacheFunction(request);

        if (cacheFunction != null && attemptReAuthentication(request, cacheFunction)) {
            httpClientCert.trace("Re-authentication succeed");
            return;
        }
        if (attemptAuthentication(request, cacheFunction)) {
            return;
        }
        httpClientCert.trace("Both, re-authentication and authentication, failed");
        fail(request);
    }

    private boolean attemptAuthentication(HttpServerRequest request, Function<SecurityDomain, IdentityCache> cacheFunction) throws HttpAuthenticationException {
        Certificate[] peerCertificates = request.getPeerCertificates();
        if (peerCertificates == null) {
            httpClientCert.trace("Peer Unverified");
            request.noAuthenticationInProgress();
            return true;
        }

        X509Certificate[] x509Certificates = X500.asX509CertificateArray(peerCertificates);
        X509PeerCertificateChainEvidence evidence = new X509PeerCertificateChainEvidence(x509Certificates);

        if (httpClientCert.isTraceEnabled()) {
            httpClientCert.tracef("Authenticating using following certificates: [%s]", Arrays.toString(x509Certificates));
        }

        EvidenceVerifyCallback callback = new EvidenceVerifyCallback(evidence);

            try {
                if (! skipVerification) {
                    MechanismUtil.handleCallbacks(httpClientCert, callbackHandler, callback);
                } else {
                    // Since handling of EvidenceVerifyCallback is being skipped here, ensure evidence
                    // decoding still takes place
                    EvidenceDecodePrincipalCallback evidenceDecodePrincipalCallback = new EvidenceDecodePrincipalCallback(evidence);
                    MechanismUtil.handleCallbacks(httpClientCert, callbackHandler, evidenceDecodePrincipalCallback);
                }
            } catch (AuthenticationMechanismException e) {
                throw e.toHttpAuthenticationException();
            } catch (UnsupportedCallbackException e) {
                throw httpClientCert.mechCallbackHandlerFailedForUnknownReason(e).toHttpAuthenticationException();
            }

        boolean verified = callback.isVerified();
        httpClientCert.tracef("X509PeerCertificateChainEvidence was verified by EvidenceVerifyCallback handler: %b  verification skipped: %b", verified, skipVerification);

        if (verified || skipVerification) {
            final BooleanSupplier authorizedFunction;
            final Callback authorizeCallBack;
            if (cacheFunction != null) {
                CachedIdentityAuthorizeCallback cacheCallback = new CachedIdentityAuthorizeCallback(evidence.getDecodedPrincipal(), cacheFunction, true);
                authorizedFunction = cacheCallback::isAuthorized;
                authorizeCallBack = cacheCallback;
            } else {
                PrincipalAuthorizeCallback principalCallback = new PrincipalAuthorizeCallback(evidence.getDecodedPrincipal());
                authorizedFunction = principalCallback::isAuthorized;
                authorizeCallBack = principalCallback;
            }

            try {
                MechanismUtil.handleCallbacks(httpClientCert, callbackHandler, authorizeCallBack);
            } catch (AuthenticationMechanismException e) {
                throw e.toHttpAuthenticationException();
            } catch (UnsupportedCallbackException e) {
                throw httpClientCert.mechCallbackHandlerFailedForUnknownReason(e).toHttpAuthenticationException();
            }

            boolean authorized = authorizedFunction.getAsBoolean();
            httpClientCert.tracef("X509PeerCertificateChainEvidence was authorized by CachedIdentityAuthorizeCallback(%s) handler: %b", evidence.getDecodedPrincipal(), authorized);
            if (authorized && succeed(request)) {
                httpClientCert.trace("Authentication succeed");
                return true;
            }
        }
        return false;
    }

    private boolean succeed(HttpServerRequest request) throws HttpAuthenticationException {
        try {
            MechanismUtil.handleCallbacks(httpClientCert, callbackHandler, AuthenticationCompleteCallback.SUCCEEDED);
            request.authenticationComplete();
            return true;
        } catch (AuthenticationMechanismException e) {
            throw e.toHttpAuthenticationException();
        } catch (UnsupportedCallbackException ignored) {
            // ignored
        }
        return false;
    }

    private void fail(HttpServerRequest request) throws HttpAuthenticationException {
        try {
            MechanismUtil.handleCallbacks(httpClientCert, callbackHandler, AuthenticationCompleteCallback.FAILED);
            request.authenticationFailed(httpClientCert.authenticationFailed());
        } catch (AuthenticationMechanismException e) {
            throw e.toHttpAuthenticationException();
        } catch (UnsupportedCallbackException ignored) {
            // ignored
        }
    }

    private boolean attemptReAuthentication(HttpServerRequest request, Function<SecurityDomain, IdentityCache> cacheFunction) throws HttpAuthenticationException {
        CachedIdentityAuthorizeCallback authorizeCallback = new CachedIdentityAuthorizeCallback(cacheFunction, true);
        try {
            MechanismUtil.handleCallbacks(httpClientCert, callbackHandler, authorizeCallback);
        } catch (AuthenticationMechanismException e) {
            throw e.toHttpAuthenticationException();
        } catch (UnsupportedCallbackException e) {
            throw httpClientCert.mechCallbackHandlerFailedForUnknownReason(e).toHttpAuthenticationException();
        }
        boolean authorized = authorizeCallback.isAuthorized();
        httpClientCert.tracef("Identity was authorized by CachedIdentityAuthorizeCallback handler: %b", authorized);
        if (authorized) {
            return succeed(request);
        }
        return false;
    }

    private Function<SecurityDomain, IdentityCache> createIdentityCacheFunction(HttpServerRequest request) {
        final HttpScope sslSessionScope = resolveScope(request, Scope.SSL_SESSION);
        final HttpScope connectionScope = resolveScope(request, Scope.CONNECTION);

        if (sslSessionScope == null && connectionScope == null) {
            return null;
        }

        return securityDomain -> new IdentityCache() {

            @Override
            public void put(SecurityIdentity identity) {
                CachedIdentity cachedIdentity = new CachedIdentity(CLIENT_CERT_NAME, false, identity);
                httpClientCert.tracef("storing into cache: %s", cachedIdentity);
                if (sslSessionScope != null) {
                    identityMap(sslSessionScope).putIfAbsent(securityDomain, cachedIdentity);
                }
                if (connectionScope != null) {
                    identityMap(connectionScope).putIfAbsent(securityDomain, cachedIdentity);
                    Certificate[] peerCertificates = request.getPeerCertificates();
                    if (peerCertificates != null) {
                        certMap(connectionScope).putIfAbsent(securityDomain, X500.asX509CertificateArray(peerCertificates));
                    }
                }
            }

            @Override
            public CachedIdentity get() {
                if (sslSessionScope != null) {
                    @SuppressWarnings("unchecked")
                    Map<SecurityDomain, CachedIdentity> identities = (Map<SecurityDomain, CachedIdentity>) sslSessionScope.getAttachment(IDENTITY_CACHE_KEY);
                    if (identities != null) {
                        CachedIdentity cached = identities.get(securityDomain);
                        if (cached != null) {
                            httpClientCert.tracef("loading from SSL_SESSION cache: %s", cached);
                            return cached;
                        }
                    }
                }
                if (connectionScope != null) {
                    @SuppressWarnings("unchecked")
                    Map<SecurityDomain, CachedIdentity> identities = (Map<SecurityDomain, CachedIdentity>) connectionScope.getAttachment(IDENTITY_CACHE_KEY);
                    if (identities != null) {
                        CachedIdentity cached = identities.get(securityDomain);
                        if (cached != null && verifyConnectionCerts(securityDomain)) {
                            httpClientCert.tracef("loading from CONNECTION cache: %s", cached);
                            return cached;
                        }
                    }
                }
                httpClientCert.tracef("loading from cache: null");
                return null;
            }

            @Override
            public CachedIdentity remove() {
                httpClientCert.tracef("clearing identity cache");
                CachedIdentity result = null;
                if (sslSessionScope != null) {
                    @SuppressWarnings("unchecked")
                    Map<SecurityDomain, CachedIdentity> identities = (Map<SecurityDomain, CachedIdentity>) sslSessionScope.getAttachment(IDENTITY_CACHE_KEY);
                    if (identities != null) result = identities.remove(securityDomain);
                }
                if (connectionScope != null) {
                    @SuppressWarnings("unchecked")
                    Map<SecurityDomain, CachedIdentity> identities = (Map<SecurityDomain, CachedIdentity>) connectionScope.getAttachment(IDENTITY_CACHE_KEY);
                    if (identities != null) {
                        CachedIdentity removed = identities.remove(securityDomain);
                        if (result == null) result = removed;
                    }
                    @SuppressWarnings("unchecked")
                    Map<SecurityDomain, X509Certificate[]> certs = (Map<SecurityDomain, X509Certificate[]>) connectionScope.getAttachment(IDENTITY_CACHE_CERTS_KEY);
                    if (certs != null) certs.remove(securityDomain);
                }
                return result;
            }

            private boolean verifyConnectionCerts(SecurityDomain domain) {
                @SuppressWarnings("unchecked")
                Map<SecurityDomain, X509Certificate[]> certs = (Map<SecurityDomain, X509Certificate[]>) connectionScope.getAttachment(IDENTITY_CACHE_CERTS_KEY);
                if (certs == null) return false;
                X509Certificate[] stored = certs.get(domain);
                if (stored == null) return false;
                Certificate[] current = request.getPeerCertificates();
                if (current == null) return false;
                return Arrays.equals(stored, X500.asX509CertificateArray(current));
            }
        };
    }

    private static HttpScope resolveScope(HttpServerRequest request, Scope scope) {
        HttpScope httpScope = request.getScope(scope);
        return (httpScope != null && httpScope.supportsAttachments()) ? httpScope : null;
    }

    private static Map<SecurityDomain, CachedIdentity> identityMap(HttpScope scope) {
        return MechanismUtil.computeIfAbsent(scope, IDENTITY_CACHE_KEY, key -> new ConcurrentHashMap<>());
    }

    private static Map<SecurityDomain, X509Certificate[]> certMap(HttpScope scope) {
        return MechanismUtil.computeIfAbsent(scope, IDENTITY_CACHE_CERTS_KEY, key -> new ConcurrentHashMap<>());
    }
}
