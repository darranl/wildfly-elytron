/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2021 Red Hat, Inc., and individual contributors
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
import org.keycloak.common.util.KeycloakUriBuilder;

import java.net.URI;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;

/**
 * Tests for {@link OidcClientUriBuilder}.
 *
 * <p>This test class verifies URI construction, template resolution,
 * query handling, path manipulation and utility methods of
 * {@code OidcClientUriBuilder}.</p>
 *
 * @author rmartinc
 */
public class OidcClientUriBuilderTest {

    // ------------------------------------------------------------------ //
    //  Basic URI builder behavior tests             //
    // ------------------------------------------------------------------ //

    @Test
    public void testKeycloakUriBuilder() {
        Assert.assertEquals("http://localhost:8080/path?attr1=value1&attr2=value2",
                KeycloakUriBuilder.fromUri("http://localhost:8080/path?attr1=value1&attr2=value2")
                        .build().toString());

        Assert.assertEquals("http://localhost/path?attr1=value1&attr2=value2",
                KeycloakUriBuilder.fromUri("http://localhost:80")
                        .path("path")
                        .queryParam("attr1", "value1")
                        .queryParam("attr2", "value2")
                        .build().toString());

        Assert.assertEquals("unknown://localhost:9000/path",
                KeycloakUriBuilder.fromUri("unknown://localhost:9000/path").build().toString());

        Assert.assertEquals("https://localhost/path?attr1=value1",
                KeycloakUriBuilder.fromUri("https://{hostname}:443/path?attr1={value}")
                        .build("localhost", "value1").toString());

        Assert.assertEquals("https://localhost:8443/path?attr1=value1",
                KeycloakUriBuilder.fromUri("https://localhost:8443/path?attr1={value}")
                        .buildFromMap(Collections.singletonMap("value", "value1")).toString());
    }

    // ================================================================== //
    //  1. Factory Methods                                                 //
    // ================================================================== //

    @Test
    public void testFromUri() {
        URI result = OidcClientUriBuilder
                .fromUri("http://localhost:8080/path?attr1=value1&attr2=value2")
                .build();
        Assert.assertEquals("http://localhost:8080/path?attr1=value1&attr2=value2", result.toString());
    }

    @Test
    public void testFromUriWithTemplateParams() {
        URI result = OidcClientUriBuilder
                .fromUri("https://{host}:8443/app?key={val}")
                .build("myhost", "myval");
        Assert.assertEquals("https://myhost:8443/app?key=myval", result.toString());
    }

    @Test
    public void testFromPath() {
        URI result = OidcClientUriBuilder
                .fromPath("/api/v1/resource")
                .build();
        Assert.assertEquals("/api/v1/resource", result.toString());
    }

    @Test
    public void testFromTemplate() {
        URI result = OidcClientUriBuilder
                .fromTemplate("https://{host}:{port}/path")
                .build("example.com", "9090");
        Assert.assertEquals("https://example.com:9090/path", result.toString());
    }

    // ================================================================== //
    //  2. URI Construction / build()                                      //
    // ================================================================== //

    @Test
    public void testBuildNoArgs() {
        URI result = OidcClientUriBuilder
                .fromUri("http://localhost:8080/simple")
                .build();
        Assert.assertEquals("http://localhost:8080/simple", result.toString());
    }

    @Test
    public void testBuildSuppressesDefaultHttpPort() {
        URI result = OidcClientUriBuilder
                .fromUri("http://localhost:80/path")
                .build();
        Assert.assertEquals("http://localhost/path", result.toString());
    }

    @Test
    public void testBuildSuppressesDefaultHttpsPort() {
        URI result = OidcClientUriBuilder
                .fromUri("https://localhost:443/path")
                .build();
        Assert.assertEquals("https://localhost/path", result.toString());
    }

    @Test
    public void testBuildPreservesNonDefaultPort() {
        URI result = OidcClientUriBuilder
                .fromUri("https://localhost:8443/path")
                .build();
        Assert.assertEquals("https://localhost:8443/path", result.toString());
    }

    @Test
    public void testBuildAsString() {
        String result = OidcClientUriBuilder
                .fromUri("http://localhost:8080/path")
                .buildAsString();
        Assert.assertEquals("http://localhost:8080/path", result);
    }

    @Test
    public void testBuildWithEncodeSlash() {
        URI result = OidcClientUriBuilder
                .fromUri("http://localhost/{path}")
                .build(new Object[]{"a/b"}, true);
        // When encodeSlashInPath=true, slash in param value gets encoded
        Assert.assertTrue(result.toString().contains("a%2Fb"));
    }

    @Test
    public void testBuildWithoutEncodeSlash() {
        URI result = OidcClientUriBuilder
                .fromUri("http://localhost/{path}")
                .build(new Object[]{"a/b"}, false);
        // When encodeSlashInPath=false, slash in param value is preserved
        Assert.assertTrue(result.toString().contains("a/b"));
    }

    @Test
    public void testResolveTemplates() {
        Map<String, Object> values = new HashMap<>();
        values.put("host", "example.com");
        values.put("id", "42");

        OidcClientUriBuilder resolved = OidcClientUriBuilder
                .fromUri("https://{host}/items/{id}")
                .resolveTemplates(values);

        URI result = resolved.build();
        Assert.assertEquals("https://example.com/items/42", result.toString());
    }

    // ================================================================== //
    //  3. Path Handling                                                    //
    // ================================================================== //

    @Test
    public void testPathAppend() {
        URI result = OidcClientUriBuilder
                .fromUri("http://localhost:8080")
                .path("api")
                .path("v1")
                .path("resource")
                .build();
        Assert.assertEquals("http://localhost:8080/api/v1/resource", result.toString());
    }

    @Test
    public void testPathAppendWithLeadingSlash() {
        URI result = OidcClientUriBuilder
                .fromUri("http://localhost:8080")
                .path("/api")
                .path("/v1")
                .build();
        Assert.assertEquals("http://localhost:8080/api/v1", result.toString());
    }

    @Test
    public void testPathAppendWithTrailingSlash() {
        URI result = OidcClientUriBuilder
                .fromUri("http://localhost:8080/base/")
                .path("child")
                .build();
        Assert.assertEquals("http://localhost:8080/base/child", result.toString());
    }

    @Test
    public void testReplacePath() {
        OidcClientUriBuilder builder = OidcClientUriBuilder
                .fromUri("http://localhost:8080/old/path");
        builder.replacePath("/new/path", true);
        URI result = builder.build();
        Assert.assertEquals("http://localhost:8080/new/path", result.toString());
    }

    @Test
    public void testReplacePathWithNull() {
        OidcClientUriBuilder builder = OidcClientUriBuilder
                .fromUri("http://localhost:8080/old/path");
        builder.replacePath(null, true);
        Assert.assertNull(builder.getPath());
    }

    // ================================================================== //
    //  4. Query Parameters                                                //
    // ================================================================== //

    @Test
    public void testQueryParamSingle() {
        URI result = OidcClientUriBuilder
                .fromUri("http://localhost:8080/path")
                .queryParam("key", "value")
                .build();
        Assert.assertEquals("http://localhost:8080/path?key=value", result.toString());
    }

    @Test
    public void testQueryParamMultiple() {
        URI result = OidcClientUriBuilder
                .fromUri("http://localhost:8080/path")
                .queryParam("a", "1")
                .queryParam("b", "2")
                .queryParam("c", "3")
                .build();
        Assert.assertEquals("http://localhost:8080/path?a=1&b=2&c=3", result.toString());
    }

    @Test
    public void testQueryParamMultipleValues() {
        URI result = OidcClientUriBuilder
                .fromUri("http://localhost:8080/path")
                .queryParam("color", "red", "blue")
                .build();
        Assert.assertEquals("http://localhost:8080/path?color=red&color=blue", result.toString());
    }

    @Test
    public void testReplaceQueryClearsWithNull() {
        OidcClientUriBuilder builder = OidcClientUriBuilder
                .fromUri("http://localhost:8080/path?existing=val");
        builder.replaceQuery(null, true);
        Assert.assertNull(builder.getQuery());
    }

    @Test
    public void testReplaceQueryClearsWithEmpty() {
        OidcClientUriBuilder builder = OidcClientUriBuilder
                .fromUri("http://localhost:8080/path?existing=val");
        builder.replaceQuery("", true);
        Assert.assertNull(builder.getQuery());
    }

    @Test
    public void testReplaceQueryParam() {
        URI result = OidcClientUriBuilder
                .fromUri("http://localhost:8080/path")
                .queryParam("a", "1")
                .queryParam("b", "2")
                .replaceQueryParam("a", "replaced")
                .build();
        String uriStr = result.toString();
        Assert.assertTrue(uriStr.contains("a=replaced"));
        Assert.assertTrue(uriStr.contains("b=2"));
        Assert.assertFalse(uriStr.contains("a=1"));
    }

    @Test
    public void testReplaceQueryParamRemovesWithNull() {
        URI result = OidcClientUriBuilder
                .fromUri("http://localhost:8080/path")
                .queryParam("a", "1")
                .queryParam("b", "2")
                .replaceQueryParam("a", (Object[]) null)
                .build();
        String uriStr = result.toString();
        Assert.assertFalse(uriStr.contains("a="));
        Assert.assertTrue(uriStr.contains("b=2"));
    }

    @Test
    public void testReplaceQueryParamAddsWhenQueryIsNull() {
        URI result = OidcClientUriBuilder
                .fromUri("http://localhost:8080/path")
                .replaceQueryParam("newKey", "newVal")
                .build();
        Assert.assertEquals("http://localhost:8080/path?newKey=newVal", result.toString());
    }

    // ================================================================== //
    //  5. Fragment                                                         //
    // ================================================================== //

    @Test
    public void testFragmentSet() {
        OidcClientUriBuilder builder = OidcClientUriBuilder
                .fromUri("http://localhost:8080/path");
        builder.fragment("section1", true);
        URI result = builder.build();
        Assert.assertEquals("http://localhost:8080/path#section1", result.toString());
    }

    @Test
    public void testFragmentClearsWithNull() {
        OidcClientUriBuilder builder = OidcClientUriBuilder
                .fromUri("http://localhost:8080/path");
        builder.fragment("section1", true);
        builder.fragment(null, true);
        Assert.assertNull(builder.getFragment());
    }

    // ================================================================== //
    //  6. User Info                                                        //
    // ================================================================== //

    @Test
    public void testUriWithUserInfo() {
        OidcClientUriBuilder builder = OidcClientUriBuilder
                .fromUri("http://admin@localhost:8080/path");
        Assert.assertEquals("admin", builder.getUserInfo());
    }

    @Test
    public void testReplaceUserInfoClearsWithNull() {
        OidcClientUriBuilder builder = OidcClientUriBuilder
                .fromUri("http://admin@localhost:8080/path");
        builder.replaceUserInfo(null, true);
        Assert.assertNull(builder.getUserInfo());
    }

    // ================================================================== //
    //  7. Matrix Parameters                                               //
    // ================================================================== //

    @Test
    public void testMatrixParam() {
        URI result = OidcClientUriBuilder
                .fromUri("http://localhost:8080/path")
                .matrixParam("color", "red")
                .build();
        Assert.assertTrue(result.toString().contains(";color=red"));
    }

    @Test
    public void testMatrixParamMultipleValues() {
        URI result = OidcClientUriBuilder
                .fromUri("http://localhost:8080/path")
                .matrixParam("color", "red", "blue")
                .build();
        String uriStr = result.toString();
        Assert.assertTrue(uriStr.contains(";color=red"));
        Assert.assertTrue(uriStr.contains(";color=blue"));
    }

    // ================================================================== //
    //  8. Getters                                                         //
    // ================================================================== //

    @Test
    public void testGetters() {
        OidcClientUriBuilder builder = OidcClientUriBuilder
                .fromUri("https://user@example.com:9090/api/v1?key=val");
        builder.fragment("frag", true);

        Assert.assertEquals("https", builder.getScheme());
        Assert.assertEquals("example.com", builder.getHost());
        Assert.assertEquals(9090, builder.getPort());
        Assert.assertEquals("user", builder.getUserInfo());
        Assert.assertNotNull(builder.getPath());
        Assert.assertTrue(builder.getPath().contains("api"));
        Assert.assertNotNull(builder.getQuery());
        Assert.assertTrue(builder.getQuery().contains("key"));
        Assert.assertEquals("frag", builder.getFragment());
    }

    @Test
    public void testGettersDefaultPort() {
        OidcClientUriBuilder builder = OidcClientUriBuilder
                .fromUri("http://localhost/path");
        Assert.assertEquals(-1, builder.getPort());
    }

    // ================================================================== //
    //  9. clone()                                                         //
    // ================================================================== //

    @Test
    public void testCloneProducesSameUri() {
        OidcClientUriBuilder original = OidcClientUriBuilder
                .fromUri("https://example.com:8443/api?key=val");
        OidcClientUriBuilder cloned = original.clone();

        Assert.assertEquals(original.build().toString(), cloned.build().toString());
    }

    @Test
    public void testCloneIsIndependent() {
        OidcClientUriBuilder original = OidcClientUriBuilder
                .fromUri("https://example.com:8443/api");
        OidcClientUriBuilder cloned = original.clone();

        cloned.path("extra");

        // Original should remain unchanged
        Assert.assertFalse(original.build().toString().contains("extra"));
        Assert.assertTrue(cloned.build().toString().contains("extra"));
    }

    // ================================================================== //
    //  10. Static Utility Methods                                         //
    // ================================================================== //

    @Test
    public void testCompareEqualStrings() {
        Assert.assertTrue(OidcClientUriBuilder.compare("hello", "hello"));
    }

    @Test
    public void testCompareSameReference() {
        String s = "test";
        Assert.assertTrue(OidcClientUriBuilder.compare(s, s));
    }

    @Test
    public void testCompareNulls() {
        Assert.assertTrue(OidcClientUriBuilder.compare(null, null));
    }

    @Test
    public void testCompareOneNull() {
        Assert.assertFalse(OidcClientUriBuilder.compare("hello", null));
        Assert.assertFalse(OidcClientUriBuilder.compare(null, "hello"));
    }

    @Test
    public void testCompareUnequalStrings() {
        Assert.assertFalse(OidcClientUriBuilder.compare("hello", "world"));
    }

    @Test
    public void testRelativizeSameHost() {
        URI from = URI.create("http://localhost/a/b");
        URI to = URI.create("http://localhost/a/c");
        URI result = OidcClientUriBuilder.relativize(from, to);
        Assert.assertEquals("../c", result.toString());
    }

    @Test
    public void testRelativizeDifferentHost() {
        URI from = URI.create("http://host1/path");
        URI to = URI.create("http://host2/path");
        URI result = OidcClientUriBuilder.relativize(from, to);
        Assert.assertEquals(to, result);
    }

    @Test
    public void testRelativizeDifferentScheme() {
        URI from = URI.create("http://localhost/path");
        URI to = URI.create("https://localhost/path");
        URI result = OidcClientUriBuilder.relativize(from, to);
        Assert.assertEquals(to, result);
    }

    @Test
    public void testRelativizeDifferentPort() {
        URI from = URI.create("http://localhost:8080/path");
        URI to = URI.create("http://localhost:9090/path");
        URI result = OidcClientUriBuilder.relativize(from, to);
        Assert.assertEquals(to, result);
    }

    @Test
    public void testRelativizeBothPathsNull() {
        URI from = URI.create("http://localhost");
        URI to = URI.create("http://localhost");
        URI result = OidcClientUriBuilder.relativize(from, to);
        Assert.assertEquals("", result.toString());
    }

    @Test
    public void testCreateUriParamMatcher() {
        Matcher matcher = OidcClientUriBuilder.createUriParamMatcher("/path/{id}/details/{name}");
        int count = 0;
        while (matcher.find()) {
            count++;
        }
        Assert.assertEquals(2, count);
    }

    @Test
    public void testGetPathParamNamesInDeclarationOrder() {
        OidcClientUriBuilder builder = OidcClientUriBuilder
                .fromUri("https://{host}/api/{version}/items/{id}?q={query}");
        List<String> params = builder.getPathParamNamesInDeclarationOrder();
        Assert.assertEquals(4, params.size());
        Assert.assertEquals("host", params.get(0));
        Assert.assertEquals("version", params.get(1));
        Assert.assertEquals("id", params.get(2));
        Assert.assertEquals("query", params.get(3));
    }

    @Test
    public void testGetPathParamNamesDeduplicates() {
        OidcClientUriBuilder builder = OidcClientUriBuilder
                .fromUri("https://{host}/{host}/path");
        List<String> params = builder.getPathParamNamesInDeclarationOrder();
        Assert.assertEquals(1, params.size());
        Assert.assertEquals("host", params.get(0));
    }

    // ================================================================== //
    //  11. Edge Cases & Error Handling                                     //
    // ================================================================== //

    @Test(expected = IllegalArgumentException.class)
    public void testUriNullThrowsException() {
        OidcClientUriBuilder.fromUri("http://localhost").uri((String) null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testUriObjectNullThrowsException() {
        OidcClientUriBuilder.fromUri("http://localhost").uri((URI) null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testBuildNullValuesThrowsException() {
        OidcClientUriBuilder.fromUri("http://localhost/{param}").build((Object[]) null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testPathNullThrowsException() {
        OidcClientUriBuilder.fromUri("http://localhost").path(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testQueryParamNullNameThrowsException() {
        OidcClientUriBuilder.fromUri("http://localhost").queryParam(null, "value");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testQueryParamNullValuesThrowsException() {
        OidcClientUriBuilder.fromUri("http://localhost").queryParam("key", (Object[]) null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testMatrixParamNullNameThrowsException() {
        OidcClientUriBuilder.fromUri("http://localhost").matrixParam(null, "value");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testMatrixParamNullValuesThrowsException() {
        OidcClientUriBuilder.fromUri("http://localhost").matrixParam("key", (Object[]) null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testBuildWithEncodeSlashNullThrowsException() {
        OidcClientUriBuilder.fromUri("http://localhost").build(null, true);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testResolveTemplatesNullThrowsException() {
        OidcClientUriBuilder.fromUri("http://localhost").resolveTemplates(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testBuildAsStringNullThrowsException() {
        OidcClientUriBuilder.fromUri("http://localhost/{p}").buildAsString((Object[]) null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testBuildInsufficientValuesThrowsException() {
        OidcClientUriBuilder.fromUri("http://localhost/{a}/{b}").build("only_one");
    }

    // ================================================================== //
    //  12. uriTemplate() and uri() methods                                //
    // ================================================================== //

    @Test
    public void testUriTemplateMethod() {
        URI result = OidcClientUriBuilder
                .fromUri("http://localhost")
                .uriTemplate("https://{host}:9090/path")
                .build("example.com");
        Assert.assertEquals("https://example.com:9090/path", result.toString());
    }

    @Test
    public void testUriStringMethod() {
        OidcClientUriBuilder builder = OidcClientUriBuilder
                .fromUri("http://old.host/old");
        builder.uri("https://new.host:9090/new");
        URI result = builder.build();
        Assert.assertEquals("https://new.host:9090/new", result.toString());
    }

    @Test
    public void testUriObjectMethod() {
        OidcClientUriBuilder builder = OidcClientUriBuilder
                .fromUri("http://localhost");
        builder.uri(URI.create("https://example.com:8443/resource?q=test#frag"));
        URI result = builder.build();
        String uriStr = result.toString();
        Assert.assertTrue(uriStr.contains("example.com"));
        Assert.assertTrue(uriStr.contains("resource"));
        Assert.assertTrue(uriStr.contains("q=test"));
        Assert.assertTrue(uriStr.contains("#frag"));
    }

    @Test
    public void testOpaqueUri() {
        OidcClientUriBuilder builder = OidcClientUriBuilder
                .fromUri("mailto:user@example.com");
        Assert.assertEquals("mailto", builder.getScheme());
    }

    @Test
    public void testUnknownSchemeWithPort() {
        URI result = OidcClientUriBuilder
                .fromUri("unknown://localhost:9000/path")
                .build();
        Assert.assertEquals("unknown://localhost:9000/path", result.toString());
    }

    // ================================================================== //
    //  13. Complex / Integration Scenarios                                //
    // ================================================================== //

    @Test
    public void testBuilderChaining() {
        URI result = OidcClientUriBuilder
                .fromUri("http://localhost:80")
                .path("api")
                .path("v1")
                .queryParam("page", "1")
                .queryParam("size", "10")
                .build();
        // Port 80 is suppressed for http
        Assert.assertEquals("http://localhost/api/v1?page=1&size=10", result.toString());
    }

    @Test
    public void testFullUriWithAllComponents() {
        URI result = OidcClientUriBuilder
                .fromUri("https://admin@example.com:8443/base")
                .path("resource")
                .queryParam("format", "json")
                .build();
        String uriStr = result.toString();
        Assert.assertTrue(uriStr.startsWith("https://"));
        Assert.assertTrue(uriStr.contains("admin@"));
        Assert.assertTrue(uriStr.contains("example.com:8443"));
        Assert.assertTrue(uriStr.contains("/base/resource"));
        Assert.assertTrue(uriStr.contains("format=json"));
    }

    @Test
    public void testTemplateWithQueryParam() {
        URI result = OidcClientUriBuilder
                .fromUri("https://localhost:8443/path?attr1={value}")
                .build("value1");
        Assert.assertEquals("https://localhost:8443/path?attr1=value1", result.toString());
    }

    @Test
    public void testTemplateWithHostAndQueryParam() {
        URI result = OidcClientUriBuilder
                .fromUri("https://{hostname}:443/path?attr1={value}")
                .build("localhost", "value1");
        // Port 443 suppressed for https
        Assert.assertEquals("https://localhost/path?attr1=value1", result.toString());
    }
}
