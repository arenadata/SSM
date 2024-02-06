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
package org.smartdata.utils;

import org.junit.Assert;
import org.junit.Test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.smartdata.utils.StringUtil.ssmPatternToRegex;
import static org.smartdata.utils.StringUtil.ssmPatternToSqlLike;
import static org.smartdata.utils.StringUtil.ssmPatternsToRegex;

/**
 * Tests for StringUtil.
 */
public class TestStringUtil {

  @Test
  public void testCmdletString() throws Exception {
    Map<String, Integer> strs = new HashMap<>();
    strs.put("int a b -c d -e f \"gg ' kk ' ff\" \" mn \"", 9);
    strs.put("cat /dir/file ", 2);

    List<String> items;
    for (String str : strs.keySet()) {
      items = StringUtil.parseCmdletString(str);
      Assert.assertTrue(strs.get(str) == items.size());
      System.out.println(items.size() + " -> " + str);
    }
  }

  @Test
  public void testSsmPatternToSqlLike() {
    Assert.assertEquals("/src/%", ssmPatternToSqlLike("/src/*"));
    Assert.assertEquals("/another_dir/test/%.bin", ssmPatternToSqlLike("/another_dir/test/*.bin"));
    Assert.assertEquals("/some/dir-_/file.%", ssmPatternToSqlLike("/some/dir-?/file.*"));
    Assert.assertEquals("/plain/path", ssmPatternToSqlLike("/plain/path"));
  }

  @Test
  public void testSsmPatternToRegex() {
    Assert.assertEquals("/src/.*", ssmPatternToRegex("/src/*"));
    Assert.assertEquals("/another_dir/test/.*\\.bin", ssmPatternToRegex("/another_dir/test/*.bin"));
    Assert.assertEquals("/some/dir_./file\\..*", ssmPatternToRegex("/some/dir_?/file.*"));
    Assert.assertEquals("/plain/path", ssmPatternToRegex("/plain/path"));
  }

  @Test
  public void testSsmPatternsToRegex() {
    List<String> ssmPatterns = Arrays.asList("/src/*", "/file_?.*", "/test_dir");
    Assert.assertEquals("(/src/.*|/file_.\\..*|/test_dir)", ssmPatternsToRegex(ssmPatterns));
  }
}
