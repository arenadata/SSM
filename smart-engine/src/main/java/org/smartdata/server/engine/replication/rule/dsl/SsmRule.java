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

import lombok.Builder;
import lombok.Value;

/**
 * Representation of the SSM rule:
 * {@code <object>: [<trigger> |] <condition> | <action>}.
 */
@Value
@Builder
public class SsmRule {
  RuleObjectType objectType;
  /** Optional trigger, rule without the trigger is checked continuously. */
  RuleTrigger trigger;
  RuleCondition condition;
  RuleAction action;

  public String render() {
    StringBuilder rule = new StringBuilder(objectType.getDslName()).append(": ");
    if (trigger != null) {
      rule.append(trigger.render()).append(" | ");
    }
    return rule.append(condition.render())
        .append(" | ")
        .append(action.render())
        .toString();
  }
}
