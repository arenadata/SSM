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
package org.smartdata.hive.fetch;

import lombok.Builder;
import lombok.Data;
import org.apache.hadoop.hive.metastore.api.NotificationEvent;

import java.util.Arrays;
import java.util.Objects;
import java.util.stream.Collectors;

@Builder
@Data
public class HiveNotificationEvent implements HmsEventStreamRecord {
  // fields from Hive event
  private final long externalId;
  private final long eventTime;
  private final String eventType;
  private final String entityType;
  private final String catalogName;
  private final String dbName;
  private final String tableName;
  private final String message;
  private final String messageFormat;

  // computed fields on SSM side
  private final String fullName;
  private long id;

  public static Builder fromMetastoreEvent(NotificationEvent event) {
    return HiveNotificationEvent.builder()
        .externalId(event.getEventId())
        .eventTime(event.getEventTime())
        .catalogName(event.getCatName())
        .dbName(event.getDbName())
        .tableName(event.getTableName())
        .message(event.getMessage())
        .messageFormat(event.getMessageFormat())
        .fullName(fullResourceName(event));
  }

  public static String fullResourceName(NotificationEvent event) {
    return fullResourceName(
        event.getCatName(),
        event.getDbName(),
        event.getTableName());
  }

  public static String fullResourceName(String... nameParts) {
    return Arrays.stream(nameParts)
        .filter(Objects::nonNull)
        .collect(Collectors.joining("."));
  }
}
