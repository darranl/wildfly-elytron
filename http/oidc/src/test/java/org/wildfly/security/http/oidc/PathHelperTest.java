/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2026 Red Hat, Inc., and individual contributors
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

/**
 * Tests for PathHelper.
 */
public class PathHelperTest {

    @Test
    public void testReplaceEnclosedCurlyBracesWithNoCurlyBraces() {
        String result = PathHelper.replaceEnclosedCurlyBraces("hello");
        Assert.assertEquals("hello", result);
    }

    @Test
    public void testReplaceEnclosedCurlyBracesWithSingleTopLevelParam() {
        String result = PathHelper.replaceEnclosedCurlyBraces("{param}");
        Assert.assertEquals("{param}", result);
    }

    @Test
    public void testReplaceEnclosedCurlyBracesWithOneNestedParam() {
        String result = PathHelper.replaceEnclosedCurlyBraces("{orderId:[0-9]{3}}");
        Assert.assertEquals("{orderId:[0-9]" + PathHelper.openCurlyReplacement + "3" + PathHelper.closeCurlyReplacement + "}", result);
    }

    @Test
    public void testReplaceEnclosedCurlyBracesWithEmptyString(){
        String result = PathHelper.replaceEnclosedCurlyBraces("");
        Assert.assertEquals("",result);
    }

    @Test
    public void testReplaceEnclosedCurlyBracesWithDeeplyNestedParam(){
        String result = PathHelper.replaceEnclosedCurlyBraces("{a:{b:{c}}}");
        Assert.assertEquals("{a:" + PathHelper.openCurlyReplacement + "b:" + PathHelper.openCurlyReplacement + "c" + PathHelper.closeCurlyReplacement + PathHelper.closeCurlyReplacement + "}", result);
    }

    @Test
    public void testRecoverEnclosedCurlyBracesWithRoundTrip(){
        String original = "{orderId:[0-9]{3}}";
        String replaced = PathHelper.replaceEnclosedCurlyBraces(original);
        String recovered = PathHelper.recoverEnclosedCurlyBraces(replaced);

        Assert.assertEquals(original,recovered);
    }

    @Test
    public void testURITemplatePatternWithRegexMatching(){
        boolean result = PathHelper.URI_TEMPLATE_PATTERN.matcher("{param}").find();
        Assert.assertTrue(result);
    }

     @Test
    public void testURIParamPatternWithRegexMatching(){
        boolean result = PathHelper.URI_PARAM_PATTERN.matcher("{orderId:[0-9]+}").find();
        Assert.assertTrue(result);
    }





}