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

import org.apache.commons.collections.CollectionUtils;

import java.util.Collection;
import java.util.StringJoiner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RegexFilterSupport {
  static final String DEFAULT_PATTERN = ".*";

  private final ThreadLocal<Matcher> patternMatcherThreadLocal;

  public RegexFilterSupport(Collection<String> patterns) {
    Pattern pattern = Pattern.compile(buildPattern(patterns));
    this.patternMatcherThreadLocal =
        ThreadLocal.withInitial(() -> pattern.matcher(""));
  }

  public boolean matches(String value) {
    return value != null
        && patternMatcherThreadLocal.get()
        .reset(value)
        .find();
  }

  static String buildPattern(Collection<String> patterns) {
    if (CollectionUtils.isEmpty(patterns)) {
      return DEFAULT_PATTERN;
    }

    StringJoiner patternBuilder = new StringJoiner("|", "(", ")");
    patterns.forEach(patternBuilder::add);
    return patternBuilder.toString();
  }
}
