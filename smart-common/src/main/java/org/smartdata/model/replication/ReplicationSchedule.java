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
package org.smartdata.model.replication;

import lombok.Builder;
import lombok.Data;

import java.time.Instant;

/**
 * Schedule of the replication, which corresponds to the trigger of the generated rules.
 */
@Data
@Builder
public class ReplicationSchedule {
  private final ReplicationScheduleType type;
  /** Interval between the {@link ReplicationScheduleType#EVERY periodic} runs. */
  private final Long intervalSeconds;
  /**
   * Time of the {@link ReplicationScheduleType#AT single} run or the start time
   * of the {@link ReplicationScheduleType#EVERY periodic} runs.
   * If not set, the replication starts immediately.
   */
  private final Instant startTime;

  /** End time of the {@link ReplicationScheduleType#EVERY periodic} runs. */
  private final Instant endTime;

  public static ReplicationSchedule eventDriven() {
    return builder().type(ReplicationScheduleType.EVENT_DRIVEN).build();
  }
}
