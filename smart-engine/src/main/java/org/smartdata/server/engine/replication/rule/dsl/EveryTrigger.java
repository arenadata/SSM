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

import java.time.Duration;
import java.time.Instant;

/**
 * Periodic trigger: {@code every <interval> [from <start> [to <end>]]}.
 */
@Value
public class EveryTrigger implements RuleTrigger {
  Duration interval;
  /** Start of the periodic checks, null means now. */
  Instant startTime;
  /** End of the periodic checks, null means forever. */
  Instant endTime;

  @Override
  public String render() {
    StringBuilder trigger = new StringBuilder("every ")
        .append(interval.getSeconds())
        .append("s");
    if (startTime != null || endTime != null) {
      trigger.append(" from ").append(RuleTrigger.renderTimePoint(startTime));
    }
    if (endTime != null) {
      trigger.append(" to ").append(RuleTrigger.renderTimePoint(endTime));
    }
    return trigger.toString();
  }
}
