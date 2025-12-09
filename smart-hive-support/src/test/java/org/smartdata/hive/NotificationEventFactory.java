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
package org.smartdata.hive;

import org.apache.hadoop.hive.metastore.TableType;
import org.apache.hadoop.hive.metastore.api.NotificationEvent;
import org.apache.hadoop.hive.metastore.messaging.AlterDatabaseMessage;
import org.apache.hadoop.hive.metastore.messaging.AlterTableMessage;
import org.apache.hadoop.hive.metastore.messaging.CreateDatabaseMessage;
import org.apache.hadoop.hive.metastore.messaging.CreateTableMessage;
import org.apache.hadoop.hive.metastore.messaging.DropDatabaseMessage;
import org.apache.hadoop.hive.metastore.messaging.DropTableMessage;
import org.apache.hadoop.hive.metastore.messaging.EventMessage;
import org.apache.hadoop.hive.metastore.messaging.MessageSerializer;
import org.apache.hadoop.hive.metastore.messaging.json.JSONAlterDatabaseMessage;
import org.apache.hadoop.hive.metastore.messaging.json.JSONAlterTableMessage;
import org.apache.hadoop.hive.metastore.messaging.json.JSONCreateDatabaseMessage;
import org.apache.hadoop.hive.metastore.messaging.json.JSONCreateTableMessage;
import org.apache.hadoop.hive.metastore.messaging.json.JSONDropDatabaseMessage;
import org.apache.hadoop.hive.metastore.messaging.json.JSONDropTableMessage;
import org.apache.hadoop.hive.metastore.messaging.json.JSONMessageEncoder;

import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.ALTER_DATABASE;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.ALTER_TABLE;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.CREATE_DATABASE;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.CREATE_TABLE;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.DROP_DATABASE;
import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.DROP_TABLE;
import static org.smartdata.hive.HiveEntityFactory.buildDb;
import static org.smartdata.hive.HiveEntityFactory.buildTable;

public class NotificationEventFactory {
  private static final MessageSerializer MESSAGE_ENCODER = new JSONMessageEncoder().getSerializer();

  public static NotificationEvent newCreateTableEvent(
      long id, String fullName, TableType tableType, String location) {
    EntityName entityName = new EntityName(fullName);
    NotificationEvent event = baseEvent(id, entityName);
    event.setEventType(CREATE_TABLE.name());

    CreateTableMessage message = new JSONCreateTableMessage(
        "server:1234",
        "serverPrincipal",
        buildTable(entityName, tableType, location),
        null,
        0L
    );

    event.setMessage(MESSAGE_ENCODER.serialize(message));
    return event;
  }

  public static NotificationEvent newCreateDbEvent(
      long id, String fullName, String location) {
    EntityName entityName = new EntityName(fullName);
    NotificationEvent event = baseEvent(id, entityName);
    event.setEventType(CREATE_DATABASE.name());

    CreateDatabaseMessage message = new JSONCreateDatabaseMessage(
        "server:1234",
        "serverPrincipal",
        buildDb(entityName, location),
        0L
    );
    event.setMessage(MESSAGE_ENCODER.serialize(message));
    return event;
  }

  public static NotificationEvent newEvent(
      long id, String fullName, EventMessage.EventType eventType) {
    return newEvent(id, fullName, eventType.toString());
  }

  public static NotificationEvent newEvent(
      long id, String fullName, String eventType) {
    EntityName entityName = new EntityName(fullName);
    NotificationEvent event = baseEvent(id, entityName);
    event.setEventType(eventType);
    return event;
  }

  public static NotificationEvent newAlterTableEvent(long id,
      TableType tableType,
      EntityInfo oldMapping,
      EntityInfo newMapping) {
    EntityName entityName = new EntityName(oldMapping.getName());
    NotificationEvent event = baseEvent(id, entityName);
    event.setEventType(ALTER_TABLE.name());

    AlterTableMessage message = new JSONAlterTableMessage(
        "server:1234",
        "serverPrincipal",
        buildTable(entityName, tableType, oldMapping.getLocation()),
        buildTable(new EntityName(newMapping.getName()), tableType, newMapping.getLocation()),
        false,
        null,
        0L
    );
    event.setMessage(MESSAGE_ENCODER.serialize(message));
    return event;
  }

  public static NotificationEvent newAlterDbEvent(long id,
      EntityInfo oldMapping, EntityInfo newMapping) {
    EntityName entityName = new EntityName(oldMapping.getName());
    NotificationEvent event = baseEvent(id, entityName);
    event.setEventType(ALTER_DATABASE.name());

    AlterDatabaseMessage message = new JSONAlterDatabaseMessage(
        "server:1234",
        "serverPrincipal",
        buildDb(entityName, oldMapping.getLocation()),
        buildDb(new EntityName(newMapping.getName()), newMapping.getLocation()),
        0L
    );
    event.setMessage(MESSAGE_ENCODER.serialize(message));
    return event;
  }

  public static NotificationEvent newDropTableEvent(
      long id, String fullName, TableType tableType, String location) {
    EntityName entityName = new EntityName(fullName);
    NotificationEvent event = baseEvent(id, entityName);
    event.setEventType(DROP_TABLE.name());

    DropTableMessage message = new JSONDropTableMessage(
        "server:1234",
        "serverPrincipal",
        buildTable(entityName, tableType, location),
        0L
    );
    event.setMessage(MESSAGE_ENCODER.serialize(message));
    return event;
  }

  public static NotificationEvent newDropDbEvent(long id, String fullName, String location) {
    EntityName entityName = new EntityName(fullName);
    NotificationEvent event = baseEvent(id, entityName);
    event.setEventType(DROP_DATABASE.name());

    DropDatabaseMessage message = new JSONDropDatabaseMessage(
        "server:1234",
        "serverPrincipal",
        buildDb(entityName, location),
        0L
    );
    event.setMessage(MESSAGE_ENCODER.serialize(message));
    return event;
  }

  private static NotificationEvent baseEvent(long id, EntityName entityName) {
    NotificationEvent event = new NotificationEvent();
    event.setEventId(id);
    event.setEventTime(0);

    event.setCatName(entityName.getCatalogName());
    event.setDbName(entityName.getDbName());
    event.setTableName(entityName.getEntityName());

    return event;
  }
}

