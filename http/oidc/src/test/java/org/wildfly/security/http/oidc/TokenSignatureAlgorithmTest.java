/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.http.oidc;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;

import jakarta.json.Json;
import jakarta.json.JsonObjectBuilder;

import mockit.Mock;
import mockit.MockUp;
import mockit.integration.junit4.JMockit;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.security.http.oidc.TokenValidator.VerifiedTokens;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.util.Base64;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

@RunWith(JMockit.class)
public class TokenSignatureAlgorithmTest {

    private static final String ISSUER_URL = "http://localhost:8080/realms/myrealm";
    private static final String SUBJECT = "alice";
    private static final String CLIENT_ID = "test-client";
    private static final String PREFERRED_USERNAME = "alice";
    private static final int EXPIRATION_OFFSET = 60;

    private static final String CLIENT_SECRET = "longerclientsecretthatisstleast512bitslongforsupportingHS512algorithm";

    @BeforeClass
    public static void setup() {
        mockIssuerUrl(ISSUER_URL);
    }

    private static void mockIssuerUrl(String issuerUrl) {
        Class<?> classToMock;
        try {
            classToMock = Class.forName("org.wildfly.security.http.oidc.OidcClientConfiguration",
                    true, OidcClientConfiguration.class.getClassLoader());
        } catch (ClassNotFoundException e) {
            throw new NoClassDefFoundError(e.getMessage());
        }
        new MockUp<Object>(classToMock) {
            @Mock
            public String getIssuerUrl() {
                return issuerUrl;
            }
        };
    }

    @Test
    public void testRS256AccessToken() throws Exception {
        testAsymmetricAlgorithm("RS256", JWSAlgorithm.RS256);
    }

    @Test
    public void testPS256AccessToken() throws Exception {
        testAsymmetricAlgorithm("PS256", JWSAlgorithm.PS256);
    }

    @Test
    public void testPS384AccessToken() throws Exception {
        testAsymmetricAlgorithm("PS384", JWSAlgorithm.PS384);
    }

    @Test
    public void testPS512AccessToken() throws Exception {
        testAsymmetricAlgorithm("PS512", JWSAlgorithm.PS512);
    }

    @Test
    public void testHS256AccessToken() throws Exception {
        testSymmetricAlgorithm("HS256", JWSAlgorithm.HS256);
    }

    @Test
    public void testHS384AccessToken() throws Exception {
        testSymmetricAlgorithm("HS384", JWSAlgorithm.HS384);
    }

    @Test
    public void testHS512AccessToken() throws Exception {
        testSymmetricAlgorithm("HS512", JWSAlgorithm.HS512);
    }

    @Test
    public void testRS256IdAndAccessToken() throws Exception {
        testAsymmetricAlgorithmWithIdToken("RS256", JWSAlgorithm.RS256);
    }

    @Test
    public void testPS256IdAndAccessToken() throws Exception {
        testAsymmetricAlgorithmWithIdToken("PS256", JWSAlgorithm.PS256);
    }

    @Test
    public void testPS384IdAndAccessToken() throws Exception {
        testAsymmetricAlgorithmWithIdToken("PS384", JWSAlgorithm.PS384);
    }

    @Test
    public void testPS512IdAndAccessToken() throws Exception {
        testAsymmetricAlgorithmWithIdToken("PS512", JWSAlgorithm.PS512);
    }

    @Test
    public void testHS256IdAndAccessToken() throws Exception {
        testSymmetricAlgorithmWithIdToken("HS256", JWSAlgorithm.HS256);
    }

    @Test
    public void testHS384IdAndAccessToken() throws Exception {
        testSymmetricAlgorithmWithIdToken("HS384", JWSAlgorithm.HS384);
    }

    @Test
    public void testHS512IdAndAccessToken() throws Exception {
        testSymmetricAlgorithmWithIdToken("HS512", JWSAlgorithm.HS512);
    }

    @Test(expected = OidcException.class)
    public void testAlgorithmConfusionRS256SignedHS256Verified() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        String token = createRSAToken(keyPair, JWSAlgorithm.RS256);

        OidcClientConfiguration clientConfiguration = createBaseConfiguration("HS256");
        clientConfiguration.setPublicKeyLocator(new HardcodedPublicKeyLocator(keyPair.getPublic()));
        clientConfiguration.setPublicClient(true);

        TokenValidator tokenValidator = TokenValidator.builder(clientConfiguration).build();

        verifyToken(tokenValidator.parseAndVerifyToken(token));
    }

    @Test(expected = OidcException.class)
    public void testAlgorithmConfusionRS256SignedPS256Verified() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        String token = createRSAToken(keyPair, JWSAlgorithm.RS256);

        OidcClientConfiguration clientConfiguration = createBaseConfiguration("PS256");
        clientConfiguration.setPublicKeyLocator(new HardcodedPublicKeyLocator(keyPair.getPublic()));
        clientConfiguration.setPublicClient(true);

        TokenValidator tokenValidator = TokenValidator.builder(clientConfiguration).build();

        verifyToken(tokenValidator.parseAndVerifyToken(token));
    }

    @Test(expected = OidcException.class)
    public void testAlgorithmConfusionPS256SignedRS256Verified() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        String token = createRSAToken(keyPair, JWSAlgorithm.PS256);

        OidcClientConfiguration clientConfiguration = createBaseConfiguration("RS256");
        clientConfiguration.setPublicKeyLocator(new HardcodedPublicKeyLocator(keyPair.getPublic()));
        clientConfiguration.setPublicClient(true);

        TokenValidator tokenValidator = TokenValidator.builder(clientConfiguration).build();

        verifyToken(tokenValidator.parseAndVerifyToken(token));
    }

    private void testAsymmetricAlgorithm(String algorithmName, JWSAlgorithm jwsAlgorithm) throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        String token = createRSAToken(keyPair, jwsAlgorithm);

        OidcClientConfiguration clientConfiguration = createBaseConfiguration(algorithmName);
        clientConfiguration.setPublicKeyLocator(new HardcodedPublicKeyLocator(keyPair.getPublic()));
        clientConfiguration.setPublicClient(true);

        TokenValidator tokenValidator = TokenValidator.builder(clientConfiguration).build();

        verifyToken(tokenValidator.parseAndVerifyToken(token));
    }

    private void testSymmetricAlgorithm(String algorithmName, JWSAlgorithm jwsAlgorithm) throws Exception {
        String token = createHMACToken(jwsAlgorithm);

        OidcClientConfiguration clientConfiguration = createBaseConfiguration(algorithmName);
        clientConfiguration.setPublicClient(false);

        ClientIdAndSecretCredentialsProvider clientSecretProvider = new ClientIdAndSecretCredentialsProvider();
        clientSecretProvider.init(clientConfiguration, CLIENT_SECRET);
        clientConfiguration.setClientAuthenticator(clientSecretProvider);

        TokenValidator tokenValidator = TokenValidator.builder(clientConfiguration).build();

        verifyToken(tokenValidator.parseAndVerifyToken(token));
    }

    private void testAsymmetricAlgorithmWithIdToken(String algorithmName, JWSAlgorithm jwsAlgorithm) throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        String accessToken = createRSAToken(keyPair, jwsAlgorithm);
        String idToken = createRSAIdToken(keyPair, jwsAlgorithm, accessToken);

        OidcClientConfiguration clientConfiguration = createBaseConfiguration(algorithmName);
        clientConfiguration.setPublicKeyLocator(new HardcodedPublicKeyLocator(keyPair.getPublic()));
        clientConfiguration.setPublicClient(true);

        TokenValidator tokenValidator = TokenValidator.builder(clientConfiguration).build();

        verifyTokens(tokenValidator.parseAndVerifyToken(idToken, accessToken));
    }

    private void testSymmetricAlgorithmWithIdToken(String algorithmName, JWSAlgorithm jwsAlgorithm) throws Exception {
        String accessToken = createHMACToken(jwsAlgorithm);
        String idToken = createHMACIdToken(jwsAlgorithm, accessToken);

        OidcClientConfiguration clientConfiguration = createBaseConfiguration(algorithmName);
        clientConfiguration.setPublicClient(false);

        ClientIdAndSecretCredentialsProvider clientSecretProvider = new ClientIdAndSecretCredentialsProvider();
        clientSecretProvider.init(clientConfiguration, CLIENT_SECRET);
        clientConfiguration.setClientAuthenticator(clientSecretProvider);

        TokenValidator tokenValidator = TokenValidator.builder(clientConfiguration).build();

        verifyTokens(tokenValidator.parseAndVerifyToken(idToken, accessToken));
    }

    private OidcClientConfiguration createBaseConfiguration(String algorithmName) {
        OidcClientConfiguration config = new OidcClientConfiguration();
        config.setClientId(CLIENT_ID);
        config.setProviderUrl(ISSUER_URL);
        config.setPrincipalAttribute("preferred_username");
        config.setSSLRequired(Oidc.SSLRequired.EXTERNAL);
        config.setTokenSignatureAlgorithm(algorithmName);
        return config;
    }

    private void verifyToken(JsonWebToken accessToken) {
        assertNotNull(accessToken);
        assertEquals(SUBJECT, accessToken.getSubject());
        assertEquals(PREFERRED_USERNAME, accessToken.getPreferredUsername());
    }

    private void verifyTokens(VerifiedTokens verifiedTokens) {
        assertNotNull(verifiedTokens);
        assertNotNull(verifiedTokens.getIdToken());
        assertNotNull(verifiedTokens.getAccessToken());

        verifyToken(verifiedTokens.getIdToken());
        verifyToken(verifiedTokens.getAccessToken());
    }

    private static String createRSAToken(KeyPair keyPair, JWSAlgorithm algorithm) throws Exception {
        PrivateKey privateKey = keyPair.getPrivate();
        JWSSigner signer = new RSASSASigner(privateKey);
        JsonObjectBuilder claimsBuilder = createClaims();

        JWSHeader header = new JWSHeader.Builder(algorithm)
                .type(new JOSEObjectType("JWT"))
                .keyID("test-key-id")
                .build();

        JWSObject jwsObject = new JWSObject(header, new Payload(claimsBuilder.build().toString()));
        jwsObject.sign(signer);
        return jwsObject.serialize();
    }

    private static String createHMACToken(JWSAlgorithm algorithm) throws Exception {
        JWSSigner signer = new MACSigner(TokenSignatureAlgorithmTest.CLIENT_SECRET.getBytes());
        JsonObjectBuilder claimsBuilder = createClaims();

        JWSHeader header = new JWSHeader.Builder(algorithm)
                .type(new JOSEObjectType("JWT"))
                .build();

        JWSObject jwsObject = new JWSObject(header, new Payload(claimsBuilder.build().toString()));
        jwsObject.sign(signer);
        return jwsObject.serialize();
    }

    private static String createRSAIdToken(KeyPair keyPair, JWSAlgorithm algorithm, String accessToken) throws Exception {
        PrivateKey privateKey = keyPair.getPrivate();
        JWSSigner signer = new RSASSASigner(privateKey);
        JsonObjectBuilder claimsBuilder = createIdTokenClaims(accessToken, algorithm.getName());

        JWSHeader header = new JWSHeader.Builder(algorithm)
                .type(new JOSEObjectType("JWT"))
                .keyID("test-key-id")
                .build();

        JWSObject jwsObject = new JWSObject(header, new Payload(claimsBuilder.build().toString()));
        jwsObject.sign(signer);
        return jwsObject.serialize();
    }

    private static String createHMACIdToken(JWSAlgorithm algorithm, String accessToken) throws Exception {
        JWSSigner signer = new MACSigner(TokenSignatureAlgorithmTest.CLIENT_SECRET.getBytes());
        JsonObjectBuilder claimsBuilder = createIdTokenClaims(accessToken, algorithm.getName());

        JWSHeader header = new JWSHeader.Builder(algorithm)
                .type(new JOSEObjectType("JWT"))
                .build();

        JWSObject jwsObject = new JWSObject(header, new Payload(claimsBuilder.build().toString()));
        jwsObject.sign(signer);
        return jwsObject.serialize();
    }

    private static JsonObjectBuilder createClaims() {
        return Json.createObjectBuilder()
                .add("sub", SUBJECT)
                .add("iss", ISSUER_URL)
                .add("aud", "account")
                .add("typ", "Bearer")
                .add("exp", (System.currentTimeMillis() / 1000) + EXPIRATION_OFFSET)
                .add("azp", CLIENT_ID)
                .add("scope", "profile email")
                .add("preferred_username", PREFERRED_USERNAME);
    }

    private static JsonObjectBuilder createIdTokenClaims(String accessToken, String algorithm) throws Exception {
        String atHash = calculateAtHash(accessToken, algorithm);
        return Json.createObjectBuilder()
                .add("sub", SUBJECT)
                .add("iss", ISSUER_URL)
                .add("aud", CLIENT_ID)
                .add("exp", (System.currentTimeMillis() / 1000) + EXPIRATION_OFFSET)
                .add("iat", System.currentTimeMillis() / 1000)
                .add("azp", CLIENT_ID)
                .add("preferred_username", PREFERRED_USERNAME)
                .add("at_hash", atHash);
    }

    private static String calculateAtHash(String accessToken, String algorithmName) throws Exception {
        String hashAlg;
        if (algorithmName.contains("256")) {
            hashAlg = "SHA-256";
        } else if (algorithmName.contains("384")) {
            hashAlg = "SHA-384";
        } else if (algorithmName.contains("512")) {
            hashAlg = "SHA-512";
        } else {
            hashAlg = "SHA-256";
        }

        MessageDigest md = MessageDigest.getInstance(hashAlg);
        byte[] hash = md.digest(accessToken.getBytes(StandardCharsets.UTF_8));
        byte[] leftHalf = new byte[hash.length / 2];
        System.arraycopy(hash, 0, leftHalf, 0, leftHalf.length);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(leftHalf);
    }
}
