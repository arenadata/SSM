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
package org.smartdata.hive.handler;

import lombok.Getter;
import org.apache.commons.lang3.EnumUtils;
import org.smartdata.hive.fetch.HiveNotificationEvent;
import org.smartdata.hive.fetch.HiveOperation;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Resolver to handle Hive metastore events happened after
 * the start and before the end of the fetching of all HMS entities.
 * We can't repeatedly save the same events in db due to some corner cases,
 * e.g., when we fetch the tables A and C from HMS, and the event id before fetching entities is 1.
 * If the following events occurred between getting the start last_event_id and fetching entities,
 * then we will lose mapping for table A: DELETE A, RENAME B to A.
 * That's why we need some kind of materialized in-memory buffer,
 * that will handle such cases before modifying the hms events table.
 */
@Getter
public abstract class HmsEntityIntermediateEventsResolver {

  private final Map<String, HiveNotificationEvent> entitiesToCreate = new HashMap<>();
  private final Set<String> entityNamesToDelete = new HashSet<>();

  public void handle(HiveNotificationEvent event) {
    HiveOperation hiveOperation = Optional.ofNullable(event.getEventType())
        .map(type -> EnumUtils.getEnum(HiveOperation.class, type))
        .orElseThrow(() -> new IllegalArgumentException("Unexpected event with unknown operation type: " + event));

    switch (hiveOperation) {
      case CREATE:
        handleCreate(event);
        break;
      case ALTER:
        handleAlter(event);
        break;
      case DROP:
        handleDrop(event);
        break;
      case UNKNOWN:
        throw new IllegalArgumentException("Unexpected event with UNKNOWN operation: " + event);
    }
  }

  protected abstract HiveNotificationEvent getUpdatedEvent(
      HiveNotificationEvent event) throws Exception;

  private void handleCreate(HiveNotificationEvent event) {
    entitiesToCreate.put(event.getFullName(), event);
  }

  private void handleDrop(HiveNotificationEvent event) {
    entitiesToCreate.remove(event.getFullName());
    entityNamesToDelete.add(event.getFullName());
  }

  private void handleAlter(HiveNotificationEvent event) {
    try {
      handleDrop(event);
      handleCreate(getUpdatedEvent(event));
    } catch (Exception e) {
      throw new RuntimeException("Error extracting updated entity from " + event, e);
    }
  }
}
