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

import org.apache.hadoop.hive.metastore.api.NotificationEvent;
import org.apache.hadoop.hive.metastore.messaging.EventMessage;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.smartdata.hive.fetch.HiveEntity.CHECK_CONSTRAINT;
import static org.smartdata.hive.fetch.HiveEntity.DATABASE;
import static org.smartdata.hive.fetch.HiveEntity.DEFAULT_CONSTRAINT;
import static org.smartdata.hive.fetch.HiveEntity.FOREIGN_KEY;
import static org.smartdata.hive.fetch.HiveEntity.FUNCTION;
import static org.smartdata.hive.fetch.HiveEntity.NOT_NULL_CONSTRAINT;
import static org.smartdata.hive.fetch.HiveEntity.PARTITION;
import static org.smartdata.hive.fetch.HiveEntity.PARTITION_COLUMN_STAT;
import static org.smartdata.hive.fetch.HiveEntity.PRIMARY_KEY;
import static org.smartdata.hive.fetch.HiveEntity.TABLE;
import static org.smartdata.hive.fetch.HiveEntity.TABLE_COLUMN_STAT;
import static org.smartdata.hive.fetch.HiveEntity.UNIQUE_CONSTRAINT;
import static org.smartdata.hive.fetch.HiveOperation.ALTER;
import static org.smartdata.hive.fetch.HiveOperation.CREATE;
import static org.smartdata.hive.fetch.HiveOperation.DROP;

public class EventOperationBuilder {
  private final Map<String, EventMessage.EventType> rawTypeToEnumMap;

  public EventOperationBuilder() {
    this.rawTypeToEnumMap = Arrays.stream(EventMessage.EventType.values())
        .collect(Collectors.toMap(
            EventMessage.EventType::toString,
            Function.identity()
        ));
  }

  public EventOperation from(NotificationEvent event) {
    return Optional.ofNullable(event.getEventType())
        .map(rawTypeToEnumMap::get)
        .map(this::toEventOperation)
        .orElse(EventOperation.unknown());
  }

  public EventOperation toEventOperation(EventMessage.EventType eventType) {
    switch (eventType) {
      case CREATE_DATABASE:
        return new EventOperation(DATABASE, CREATE);
      case DROP_DATABASE:
        return new EventOperation(DATABASE, DROP);
      case CREATE_TABLE:
        return new EventOperation(TABLE, CREATE);
      case DROP_TABLE:
        return new EventOperation(TABLE, DROP);
      case ADD_PARTITION:
        return new EventOperation(PARTITION, CREATE);
      case DROP_PARTITION:
        return new EventOperation(PARTITION, DROP);
      case ALTER_DATABASE:
        return new EventOperation(DATABASE, ALTER);
      case ALTER_TABLE:
        return new EventOperation(TABLE, ALTER);
      case ADD_PRIMARYKEY:
        return new EventOperation(PRIMARY_KEY, CREATE);
      case ADD_FOREIGNKEY:
        return new EventOperation(FOREIGN_KEY, CREATE);
      case ADD_UNIQUECONSTRAINT:
        return new EventOperation(UNIQUE_CONSTRAINT, CREATE);
      case ADD_NOTNULLCONSTRAINT:
        return new EventOperation(NOT_NULL_CONSTRAINT, CREATE);
      case ADD_DEFAULTCONSTRAINT:
        return new EventOperation(DEFAULT_CONSTRAINT, CREATE);
      case ADD_CHECKCONSTRAINT:
        return new EventOperation(CHECK_CONSTRAINT, CREATE);
      case DROP_CONSTRAINT:
        return new EventOperation(DEFAULT_CONSTRAINT, DROP);
      case ALTER_PARTITION:
        return new EventOperation(PARTITION, ALTER);
      case CREATE_FUNCTION:
        return new EventOperation(FUNCTION, CREATE);
      case DROP_FUNCTION:
        return new EventOperation(FUNCTION, DROP);
      case UPDATE_TABLE_COLUMN_STAT:
        return new EventOperation(TABLE_COLUMN_STAT, ALTER);
      case DELETE_TABLE_COLUMN_STAT:
        return new EventOperation(TABLE_COLUMN_STAT, DROP);
      case UPDATE_PARTITION_COLUMN_STAT:
        return new EventOperation(PARTITION_COLUMN_STAT, ALTER);
      case DELETE_PARTITION_COLUMN_STAT:
        return new EventOperation(PARTITION_COLUMN_STAT, DROP);
      // it's an internal event type
      case UPDATE_PARTITION_COLUMN_STAT_BATCH:
        // the event types below are not produced by the Hive DbNotificationListener
      case DROP_DATACONNECTOR:
      case CREATE_DATACONNECTOR:
      case ALTER_DATACONNECTOR:
      case CREATE_ISCHEMA:
      case ALTER_ISCHEMA:
      case DROP_ISCHEMA:
      case ADD_SCHEMA_VERSION:
      case ALTER_SCHEMA_VERSION:
      case DROP_SCHEMA_VERSION:
      case CREATE_CATALOG:
      case ALTER_CATALOG:
      case DROP_CATALOG:
        // the event types below are not handled intentionally,
        // we don't collapse them into a single branch just to explicitly show this
      case INSERT:
      case ALLOC_WRITE_ID:
      case OPEN_TXN:
      case COMMIT_TXN:
      case ABORT_TXN:
      case ACID_WRITE:
      case BATCH_ACID_WRITE:
      case COMMIT_COMPACTION:
      case RELOAD:
        // do nothing
        return EventOperation.ignored();
    }

    return EventOperation.ignored();
  }
}
