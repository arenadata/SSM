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

package org.smartdata.hive.snapshot;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.hadoop.hive.metastore.Warehouse;
import org.apache.hadoop.hive.metastore.api.Database;
import org.apache.hadoop.hive.metastore.api.Function;
import org.apache.hadoop.hive.metastore.api.MetaException;
import org.apache.hadoop.hive.metastore.api.Partition;
import org.apache.hadoop.hive.metastore.api.SQLCheckConstraint;
import org.apache.hadoop.hive.metastore.api.SQLDefaultConstraint;
import org.apache.hadoop.hive.metastore.api.SQLForeignKey;
import org.apache.hadoop.hive.metastore.api.SQLNotNullConstraint;
import org.apache.hadoop.hive.metastore.api.SQLPrimaryKey;
import org.apache.hadoop.hive.metastore.api.SQLUniqueConstraint;
import org.apache.hadoop.hive.metastore.api.Table;
import org.apache.hadoop.hive.metastore.messaging.AddCheckConstraintMessage;
import org.apache.hadoop.hive.metastore.messaging.AddDefaultConstraintMessage;
import org.apache.hadoop.hive.metastore.messaging.AddForeignKeyMessage;
import org.apache.hadoop.hive.metastore.messaging.AddNotNullConstraintMessage;
import org.apache.hadoop.hive.metastore.messaging.AddPartitionMessage;
import org.apache.hadoop.hive.metastore.messaging.AddPrimaryKeyMessage;
import org.apache.hadoop.hive.metastore.messaging.AddUniqueConstraintMessage;
import org.apache.hadoop.hive.metastore.messaging.CreateDatabaseMessage;
import org.apache.hadoop.hive.metastore.messaging.CreateFunctionMessage;
import org.apache.hadoop.hive.metastore.messaging.CreateTableMessage;
import org.apache.hadoop.hive.metastore.messaging.EventMessage;
import org.apache.hadoop.hive.metastore.messaging.MessageBuilder;
import org.apache.hadoop.hive.metastore.messaging.MessageEncoder;
import org.smartdata.hive.fetch.HiveEntity;
import org.smartdata.hive.fetch.HiveNotificationEvent;
import org.smartdata.hive.fetch.HiveOperation;

import java.util.Collections;

import static org.smartdata.hive.fetch.HiveNotificationEvent.fullResourceName;

@Slf4j
@Getter
public class HiveNotificationEventFactory {
  private final MessageEncoder messageEncoder;
  private final String messageFormat;

  public HiveNotificationEventFactory(MessageEncoder messageEncoder) {
    this.messageEncoder = messageEncoder;
    this.messageFormat = messageEncoder.getMessageFormat();
  }

  public HiveNotificationEvent createDbEvent(Database database, long diffId) {
    log.debug("Saving a new db from metastore: {}", database.getName());

    CreateDatabaseMessage message = MessageBuilder.getInstance()
        .buildCreateDatabaseMessage(database);

    return eventBuilder(database.getCatalogName(), message, diffId)
        .fullName(fullResourceName(database.getName()))
        .entityType(HiveEntity.DATABASE.toString())
        .dbName(database.getName())
        .build();
  }

  public HiveNotificationEvent createTableEvent(Table table, long diffId) {
    log.debug("Saving a new table from metastore: {}", table.getTableName());

    // we don't use filenames in the handler
    CreateTableMessage message = MessageBuilder.getInstance()
        .buildCreateTableMessage(table, Collections.emptyIterator());

    return eventBuilder(table.getCatName(), message, diffId)
        .fullName(fullName(table))
        .entityType(HiveEntity.TABLE.toString())
        .dbName(table.getDbName())
        .tableName(table.getTableName())
        .build();
  }

  public HiveNotificationEvent createPartitionEvent(Table table, Partition partition, long diffId) {
    String partitionKey = partitionName(table, partition);
    log.debug("Saving a new partition from metastore: {}", partitionKey);

    // we don't use filenames in the handler
    AddPartitionMessage message = MessageBuilder.getInstance()
        .buildAddPartitionMessage(table,
            Collections.singletonList(partition).iterator(),
            Collections.emptyIterator());

    return eventBuilder(partition.getCatName(), message, diffId)
        .fullName(partitionKey)
        .entityType(HiveEntity.PARTITION.toString())
        .dbName(partition.getDbName())
        .tableName(partition.getTableName())
        .build();
  }

  public HiveNotificationEvent createFunctionEvent(Function function, long diffId) {
    String resourceName = fullName(function);
    log.debug("Saving a new function from metastore: {}", resourceName);

    CreateFunctionMessage message = MessageBuilder.getInstance()
        .buildCreateFunctionMessage(function);

    return eventBuilder(function.getCatName(), message, diffId)
        .fullName(resourceName)
        .entityType(HiveEntity.FUNCTION.toString())
        .dbName(function.getDbName())
        .build();
  }

  public HiveNotificationEvent createPrimaryKeyEvent(SQLPrimaryKey constraint, long diffId) {
    String pKeyName = fullName(constraint);
    log.debug("Saving a new primary key from metastore: {}", pKeyName);

    AddPrimaryKeyMessage message = MessageBuilder.getInstance()
        .buildAddPrimaryKeyMessage(Collections.singletonList(constraint));

    return eventBuilder(constraint.getCatName(), message, diffId)
        .fullName(pKeyName)
        .entityType(HiveEntity.PRIMARY_KEY.toString())
        .dbName(constraint.getTable_db())
        .tableName(constraint.getTable_name())
        .build();
  }

  public HiveNotificationEvent createForeignKeyEvent(
      SQLForeignKey constraint, long diffId) {
    String fKeyName = fullName(constraint);
    log.debug("Saving a new foreign key from metastore: {}", fKeyName);

    AddForeignKeyMessage message = MessageBuilder.getInstance()
        .buildAddForeignKeyMessage(Collections.singletonList(constraint));

    return eventBuilder(constraint.getCatName(), message, diffId)
        .fullName(fKeyName)
        .entityType(HiveEntity.FOREIGN_KEY.toString())
        .dbName(constraint.getFktable_db())
        .tableName(constraint.getFktable_name())
        .relatedResources(Collections.singleton(
            fullResourceName(constraint.getPktable_db(), constraint.getPktable_db())))
        .build();
  }

  public HiveNotificationEvent createUniqueConstraintEvent(
      SQLUniqueConstraint constraint, long diffId) {
    String constraintName = fullName(constraint);
    log.debug("Saving a new unique constraint from metastore: {}", constraintName);

    AddUniqueConstraintMessage message = MessageBuilder.getInstance()
        .buildAddUniqueConstraintMessage(Collections.singletonList(constraint));

    return eventBuilder(constraint.getCatName(), message, diffId)
        .fullName(constraintName)
        .entityType(HiveEntity.UNIQUE_CONSTRAINT.toString())
        .dbName(constraint.getTable_db())
        .tableName(constraint.getTable_name())
        .build();
  }

  public HiveNotificationEvent createNotNullConstraintEvent(
      SQLNotNullConstraint constraint, long diffId) {
    String constraintName = fullName(constraint);
    log.debug("Saving a new not null constraint from metastore: {}", constraintName);

    AddNotNullConstraintMessage message = MessageBuilder.getInstance()
        .buildAddNotNullConstraintMessage(Collections.singletonList(constraint));

    return eventBuilder(constraint.getCatName(), message, diffId)
        .fullName(constraintName)
        .entityType(HiveEntity.NOT_NULL_CONSTRAINT.toString())
        .dbName(constraint.getTable_db())
        .tableName(constraint.getTable_name())
        .build();
  }

  public HiveNotificationEvent createDefaultConstraintEvent(
      SQLDefaultConstraint constraint, long diffId) {
    String constraintName = fullName(constraint);
    log.debug("Saving a new default constraint from metastore: {}", constraintName);

    AddDefaultConstraintMessage message = MessageBuilder.getInstance()
        .buildAddDefaultConstraintMessage(Collections.singletonList(constraint));

    return eventBuilder(constraint.getCatName(), message, diffId)
        .fullName(constraintName)
        .entityType(HiveEntity.DEFAULT_CONSTRAINT.toString())
        .dbName(constraint.getTable_db())
        .tableName(constraint.getTable_name())
        .build();
  }

  public HiveNotificationEvent createCheckConstraintEvent(
      SQLCheckConstraint constraint, long diffId) {
    String constraintName = fullName(constraint);
    log.debug("Saving a new check constraint from metastore: {}", constraintName);

    AddCheckConstraintMessage message = MessageBuilder.getInstance()
        .buildAddCheckConstraintMessage(Collections.singletonList(constraint));

    return eventBuilder(constraint.getCatName(), message, diffId)
        .fullName(constraintName)
        .entityType(HiveEntity.CHECK_CONSTRAINT.toString())
        .dbName(constraint.getTable_db())
        .tableName(constraint.getTable_name())
        .build();
  }

  public static String partitionName(Table table, Partition partition) {
    try {
      return fullResourceName(partition.getDbName(), partition.getTableName(),
          Warehouse.makePartName(table.getPartitionKeys(), partition.getValues()));
    } catch (MetaException e) {
      throw new IllegalArgumentException("Error creating partition name", e);
    }
  }

  public static String fullName(Table table) {
    return fullResourceName(
        table.getDbName(),
        table.getTableName()
    );
  }

  public static String fullName(Function function) {
    return fullResourceName(function.getDbName(), function.getFunctionName());
  }

  public static String fullName(SQLPrimaryKey constraint) {
    return fullResourceName(
        constraint.getTable_db(),
        constraint.getTable_name(),
        constraint.getPk_name()
    );
  }

  public static String fullName(SQLForeignKey constraint) {
    return fullResourceName(
        constraint.getFktable_db(),
        constraint.getFktable_name(),
        constraint.getFk_name()
    );
  }

  public static String fullName(SQLUniqueConstraint constraint) {
    return fullResourceName(
        constraint.getTable_db(),
        constraint.getTable_name(),
        constraint.getUk_name()
    );
  }

  public static String fullName(SQLNotNullConstraint constraint) {
    return fullResourceName(
        constraint.getTable_db(),
        constraint.getTable_name(),
        constraint.getNn_name()
    );
  }

  public static String fullName(SQLDefaultConstraint constraint) {
    return fullResourceName(
        constraint.getTable_db(),
        constraint.getTable_name(),
        constraint.getDc_name()
    );
  }

  public static String fullName(SQLCheckConstraint constraint) {
    return fullResourceName(
        constraint.getTable_db(),
        constraint.getTable_name(),
        constraint.getDc_name()
    );
  }

  private HiveNotificationEvent.Builder eventBuilder(String catalog, EventMessage message, long diffId) {
    return HiveNotificationEvent.builder()
        .externalId(diffId)
        .eventType(HiveOperation.CREATE.toString())
        .catalogName(catalog)
        .message(messageEncoder.getSerializer().serialize(message))
        .messageFormat(messageFormat);
  }
}