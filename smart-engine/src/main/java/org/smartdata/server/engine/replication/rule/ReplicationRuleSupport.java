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

import org.apache.commons.collections4.CollectionUtils;
import org.smartdata.model.replication.ReplicationSchedule;
import org.smartdata.model.replication.ReplicationSource;
import org.smartdata.model.replication.SourceTable;
import org.smartdata.server.engine.replication.rule.dsl.AtTrigger;
import org.smartdata.server.engine.replication.rule.dsl.EveryTrigger;
import org.smartdata.server.engine.replication.rule.dsl.RuleTrigger;

import java.time.Duration;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

/**
 * Common logic of the replication rule generators.
 */
final class ReplicationRuleSupport {

  static RuleTrigger toTrigger(ReplicationSchedule schedule) {
    switch (schedule.getType()) {
      case EVENT_DRIVEN:
        return null;
      case EVERY:
        return new EveryTrigger(Duration.ofSeconds(schedule.getIntervalSeconds()),
            schedule.getStartTime(), schedule.getEndTime());
      case AT:
        return new AtTrigger(schedule.getStartTime());
      default:
        throw new IllegalArgumentException("Unsupported schedule type: " + schedule.getType());
    }
  }

  /**
   * Renders the value of the action argument with the included events.
   *
   * @return comma-separated names of the events or an empty optional, if the events
   *     don't restrict the replication: omitted, empty and all the events mean all events
   */
  static <EnumT extends Enum<EnumT>> Optional<String> includedEvents(
      Set<EnumT> events, Set<EnumT> allEvents) {
    if (CollectionUtils.isEmpty(events) || events.containsAll(allEvents)) {
      return Optional.empty();
    }
    return Optional.of(events.stream()
        .sorted()
        .map(Enum::name)
        .collect(Collectors.joining(",")));
  }
}
