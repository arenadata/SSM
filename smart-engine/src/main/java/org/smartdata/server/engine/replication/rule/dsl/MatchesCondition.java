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
package org.smartdata.server.engine.replication.rule.dsl;

import lombok.Value;

/**
 * Glob pattern match of the object property: {@code <property> matches "<pattern>"}.
 */
@Value
public class MatchesCondition implements RuleCondition {
  String property;
  String pattern;

  public MatchesCondition(String property, String pattern) {
    // string literals of the rule DSL don't support escaping
    if (pattern.contains("\"")) {
      throw new IllegalArgumentException("Rule pattern can't contain quotes: " + pattern);
    }
    this.property = property;
    this.pattern = pattern;
  }

  public static MatchesCondition pathMatches(String pattern) {
    return new MatchesCondition("path", pattern);
  }

  public static MatchesCondition nameMatches(String pattern) {
    return new MatchesCondition("name", pattern);
  }

  @Override
  public String render() {
    return property + " matches \"" + pattern + "\"";
  }
}
