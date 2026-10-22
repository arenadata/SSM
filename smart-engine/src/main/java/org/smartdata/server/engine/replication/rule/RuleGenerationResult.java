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
package org.smartdata.server.engine.replication.rule;

import lombok.Value;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Value
public class RuleGenerationResult {
  List<GeneratedRule> rules;

  public static RuleGenerationResult empty() {
    return new RuleGenerationResult(Collections.emptyList());
  }

  public RuleGenerationResult merge(RuleGenerationResult other) {
    List<GeneratedRule> mergedRules = new ArrayList<>(rules);
    mergedRules.addAll(other.getRules());
    return new RuleGenerationResult(mergedRules);
  }

  public List<String> renderRules() {
    return rules.stream()
        .map(rule -> rule.getRule().render())
        .collect(Collectors.toList());
  }
}
