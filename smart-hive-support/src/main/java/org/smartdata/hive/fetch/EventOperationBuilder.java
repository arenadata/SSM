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

import java.util.Optional;

import static org.smartdata.hive.fetch.HiveEntity.CATALOG;
import static org.smartdata.hive.fetch.HiveEntity.CONNECTOR;
import static org.smartdata.hive.fetch.HiveEntity.DATABASE;
import static org.smartdata.hive.fetch.HiveEntity.FUNCTION;
import static org.smartdata.hive.fetch.HiveEntity.PARTITION;
import static org.smartdata.hive.fetch.HiveEntity.TABLE;
import static org.smartdata.hive.fetch.HiveOperation.ALTER;
import static org.smartdata.hive.fetch.HiveOperation.CREATE;
import static org.smartdata.hive.fetch.HiveOperation.DROP;

public class EventOperationBuilder {
  public EventOperation from(NotificationEvent event) {
    return extractEventType(event)
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
      case ADD_PRIMARYKEY:
      case ADD_FOREIGNKEY:
      case ADD_UNIQUECONSTRAINT:
      case ADD_NOTNULLCONSTRAINT:
      case ADD_DEFAULTCONSTRAINT:
      case ADD_CHECKCONSTRAINT:
      case DROP_CONSTRAINT:
        return new EventOperation(TABLE, ALTER);
      case ALTER_PARTITION:
        return new EventOperation(PARTITION, ALTER);
      case CREATE_FUNCTION:
        return new EventOperation(FUNCTION, CREATE);
      case DROP_FUNCTION:
        return new EventOperation(FUNCTION, DROP);
      case CREATE_CATALOG:
        return new EventOperation(CATALOG, CREATE);
      case DROP_CATALOG:
        return new EventOperation(CATALOG, DROP);
      case ALTER_CATALOG:
        return new EventOperation(CATALOG, ALTER);
      case CREATE_DATACONNECTOR:
        return new EventOperation(CONNECTOR, CREATE);
      case DROP_DATACONNECTOR:
        return new EventOperation(CONNECTOR, DROP);
      case ALTER_DATACONNECTOR:
        return new EventOperation(CONNECTOR, ALTER);
      case INSERT:
      case ALLOC_WRITE_ID:
      case CREATE_ISCHEMA:
      case ALTER_ISCHEMA:
      case DROP_ISCHEMA:
      case ADD_SCHEMA_VERSION:
      case ALTER_SCHEMA_VERSION:
      case DROP_SCHEMA_VERSION:
      case OPEN_TXN:
      case COMMIT_TXN:
      case ABORT_TXN:
      case ACID_WRITE:
      case BATCH_ACID_WRITE:
      case UPDATE_TABLE_COLUMN_STAT:
      case DELETE_TABLE_COLUMN_STAT:
      case UPDATE_PARTITION_COLUMN_STAT:
      case UPDATE_PARTITION_COLUMN_STAT_BATCH:
      case DELETE_PARTITION_COLUMN_STAT:
      case COMMIT_COMPACTION:
      case RELOAD:
        // do nothing
        return EventOperation.ignored();
    }

    return EventOperation.ignored();
  }

  private Optional<EventMessage.EventType> extractEventType(NotificationEvent event) {
    try {
      return Optional.ofNullable(event.getEventType())
          .map(EventMessage.EventType::valueOf);
    } catch (IllegalArgumentException e) {
      return Optional.empty();
    }
  }
}
