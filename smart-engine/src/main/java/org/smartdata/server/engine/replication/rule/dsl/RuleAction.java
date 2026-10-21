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

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Action part of the rule: {@code <name> [-arg value] [-flag]}.
 */
@EqualsAndHashCode
@ToString
@Getter
public class RuleAction {
  private final String name;
  /** Ordered action arguments, the flags have null values. */
  private final Map<String, String> args;

  private RuleAction(String name) {
    this.name = name;
    this.args = new LinkedHashMap<>();
  }

  public static RuleAction action(String name) {
    return new RuleAction(name);
  }

  public RuleAction arg(String argName, String value) {
    args.put(argName, value);
    return this;
  }

  public RuleAction flag(String flagName) {
    args.put(flagName, null);
    return this;
  }

  public String render() {
    StringBuilder action = new StringBuilder(name);
    args.forEach((argName, value) -> {
      action.append(" ").append(argName);
      if (value != null) {
        action.append(" ").append(quoteIfNeeded(value));
      }
    });
    return action.toString();
  }

  // the cmdlet parser treats the quoted value with whitespaces as a single argument
  private static String quoteIfNeeded(String value) {
    return value.chars().anyMatch(Character::isWhitespace)
        ? "\"" + value + "\""
        : value;
  }
}
