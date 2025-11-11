/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.smartdata.model;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.smartdata.model.RegexFilterSupport.DEFAULT_PATTERN;

@RunWith(Parameterized.class)
public class RegexFilterSupportTest {
  @Parameterized.Parameter
  public List<String> patterns;

  @Parameterized.Parameter(1)
  public String expectedResult;

  @Parameterized.Parameters(
      name = "patterns = {0}, expectedResult = {1}")
  public static Object[] parameters() {
    return new Object[][]{
        {Collections.emptyList(), DEFAULT_PATTERN},
        {Collections.singletonList("first"), "(first)"},
        {Arrays.asList("first", ".*second", ".*third.*"), "(first|.*second|.*third.*)"}
    };
  }

  @Test
  public void testBuildPattern() {
    String pattern = RegexFilterSupport.buildPattern(patterns);
    Assert.assertEquals(expectedResult, pattern);
  }
}
