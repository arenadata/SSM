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

import lombok.extern.slf4j.Slf4j;
import org.apache.hadoop.hive.metastore.Warehouse;
import org.apache.hadoop.hive.metastore.api.Catalog;
import org.apache.hadoop.hive.metastore.api.Database;
import org.apache.hadoop.hive.metastore.api.Function;
import org.apache.hadoop.hive.metastore.api.Partition;
import org.apache.hadoop.hive.metastore.api.SQLCheckConstraint;
import org.apache.hadoop.hive.metastore.api.SQLDefaultConstraint;
import org.apache.hadoop.hive.metastore.api.SQLForeignKey;
import org.apache.hadoop.hive.metastore.api.SQLNotNullConstraint;
import org.apache.hadoop.hive.metastore.api.SQLPrimaryKey;
import org.apache.hadoop.hive.metastore.api.SQLUniqueConstraint;
import org.apache.hadoop.hive.metastore.api.Table;
import org.apache.hadoop.hive.metastore.messaging.MessageBuilder;
import org.apache.hadoop.hive.metastore.messaging.MessageEncoder;
import org.apache.hadoop.hive.metastore.messaging.MessageSerializer;
import org.apache.thrift.TException;
import org.smartdata.hive.fetch.HiveEntity;
import org.smartdata.hive.fetch.HiveNotificationEvent;
import org.smartdata.hive.fetch.HiveOperation;

import static org.smartdata.hive.fetch.HiveNotificationEvent.fullResourceName;

@Slf4j
public class HiveNotificationEventFactory {
  private final MessageSerializer hmsEntitySerializerWrapper;
  private final String messageFormat;

  public HiveNotificationEventFactory(MessageEncoder messageEncoder) {
    this.hmsEntitySerializerWrapper = messageEncoder.getSerializer();
    this.messageFormat = messageEncoder.getMessageFormat();
  }

  public HiveNotificationEvent createCatalogEvent(Catalog catalog, long diffId) throws TException {
    log.debug("Saving a new catalog from metastore: {}", catalog.getName());

    return eventBuilder(catalog.getName(), diffId)
        .fullName(fullResourceName(catalog.getName()))
        .entityType(HiveEntity.CATALOG.toString())
        .message(wrap(MessageBuilder.createCatalogObjJson(catalog)))
        .build();
  }

  public HiveNotificationEvent createDbEvent(String catalog, Database database, long diffId) throws TException {
    log.debug("Saving a new db from metastore: {}", database.getName());

    return eventBuilder(catalog, diffId)
        .fullName(fullResourceName(catalog, database.getName()))
        .entityType(HiveEntity.DATABASE.toString())
        .dbName(database.getName())
        .message(wrap(MessageBuilder.createDatabaseObjJson(database)))
        .build();
  }

  public HiveNotificationEvent createTableEvent(Table table, long diffId) throws TException {
    log.debug("Saving a new table from metastore: {}", table.getTableName());

    return eventBuilder(table.getCatName(), diffId)
        .fullName(fullResourceName(table.getCatName(), table.getDbName(), table.getTableName()))
        .entityType(HiveEntity.TABLE.toString())
        .dbName(table.getDbName())
        .message(wrap(MessageBuilder.createTableObjJson(table)))
        .build();
  }

  public HiveNotificationEvent createPartitionEvent(Table table, Partition partition, long diffId) throws TException {
    String partitionKey = fullResourceName(partition.getCatName(), partition.getDbName(), partition.getTableName(),
        Warehouse.makePartName(table.getPartitionKeys(), partition.getValues()));
    log.debug("Saving a new partition from metastore: {}", partitionKey);

    return eventBuilder(partition.getCatName(), diffId)
        .fullName(partitionKey)
        .entityType(HiveEntity.PARTITION.toString())
        .dbName(partition.getDbName())
        .message(wrap(MessageBuilder.createPartitionObjJson(partition)))
        .build();
  }

  public HiveNotificationEvent createFunctionEvent(Function function, long diffId) throws TException {
    String resourceName = fullResourceName(function.getCatName(), function.getDbName(), function.getFunctionName());
    log.debug("Saving a new function from metastore: {}", resourceName);

    return eventBuilder(function.getCatName(), diffId)
        .fullName(resourceName)
        .entityType(HiveEntity.FUNCTION.toString())
        .dbName(function.getDbName())
        .message(wrap(MessageBuilder.createFunctionObjJson(function)))
        .build();
  }

  public HiveNotificationEvent createPrimaryKeyEvent(SQLPrimaryKey constraint, long diffId) throws TException {
    String pKeyName = fullName(constraint);
    log.debug("Saving a new primary key from metastore: {}", pKeyName);

    return eventBuilder(constraint.getCatName(), diffId)
        .fullName(pKeyName)
        .entityType(HiveEntity.PRIMARY_KEY.toString())
        .dbName(constraint.getTable_db())
        .message(wrap(MessageBuilder.createPrimaryKeyObjJson(constraint)))
        .build();
  }

  public HiveNotificationEvent createForeignKeyEvent(
      SQLForeignKey constraint, long diffId) throws TException {
    String fKeyName = fullName(constraint);
    log.debug("Saving a new foreign key from metastore: {}", fKeyName);

    return eventBuilder(constraint.getCatName(), diffId)
        .fullName(fKeyName)
        .entityType(HiveEntity.FOREIGN_KEY.toString())
        .dbName(constraint.getFktable_db())
        .message(wrap(MessageBuilder.createForeignKeyObjJson(constraint)))
        .build();
  }

  public HiveNotificationEvent createUniqueConstraintEvent(
      SQLUniqueConstraint constraint, long diffId) throws TException {
    String constraintName = fullName(constraint);
    log.debug("Saving a new unique constraint from metastore: {}", constraintName);

    return eventBuilder(constraint.getCatName(), diffId)
        .fullName(constraintName)
        .entityType(HiveEntity.UNIQUE_CONSTRAINT.toString())
        .dbName(constraint.getTable_db())
        .message(wrap(MessageBuilder.createUniqueConstraintObjJson(constraint)))
        .build();
  }

  public HiveNotificationEvent createNotNullConstraintEvent(
      SQLNotNullConstraint constraint, long diffId) throws TException {
    String constraintName = fullName(constraint);
    log.debug("Saving a new not null constraint from metastore: {}", constraintName);

    return eventBuilder(constraint.getCatName(), diffId)
        .fullName(constraintName)
        .entityType(HiveEntity.NOT_NULL_CONSTRAINT.toString())
        .dbName(constraint.getTable_db())
        .message(wrap(MessageBuilder.createNotNullConstraintObjJson(constraint)))
        .build();
  }

  public HiveNotificationEvent createDefaultConstraintEvent(
      SQLDefaultConstraint constraint, long diffId) throws TException {
    String constraintName = fullName(constraint);
    log.debug("Saving a new default constraint from metastore: {}", constraintName);

    return eventBuilder(constraint.getCatName(), diffId)
        .fullName(constraintName)
        .entityType(HiveEntity.DEFAULT_CONSTRAINT.toString())
        .dbName(constraint.getTable_db())
        .message(wrap(MessageBuilder.createDefaultConstraintObjJson(constraint)))
        .build();
  }

  public HiveNotificationEvent createCheckConstraintEvent(
      SQLCheckConstraint constraint, long diffId) throws TException {
    String constraintName = fullName(constraint);
    log.debug("Saving a new check constraint from metastore: {}", constraintName);

    return eventBuilder(constraint.getCatName(), diffId)
        .fullName(constraintName)
        .entityType(HiveEntity.CHECK_CONSTRAINT.toString())
        .dbName(constraint.getTable_db())
        .message(wrap(MessageBuilder.createCheckConstraintObjJson(constraint)))
        .build();
  }

  public static String fullName(SQLPrimaryKey constraint) {
    return fullResourceName(
        constraint.getCatName(),
        constraint.getTable_db(),
        constraint.getTable_name(),
        constraint.getPk_name()
    );
  }

  public static String fullName(SQLForeignKey constraint) {
    return fullResourceName(
        constraint.getCatName(),
        constraint.getFktable_db(),
        constraint.getFktable_name(),
        constraint.getFk_name()
    );
  }

  public static String fullName(SQLUniqueConstraint constraint) {
    return fullResourceName(
        constraint.getCatName(),
        constraint.getTable_db(),
        constraint.getTable_name(),
        constraint.getUk_name()
    );
  }

  public static String fullName(SQLNotNullConstraint constraint) {
    return fullResourceName(
        constraint.getCatName(),
        constraint.getTable_db(),
        constraint.getTable_name(),
        constraint.getNn_name()
    );
  }

  public static String fullName(SQLDefaultConstraint constraint) {
    return fullResourceName(
        constraint.getCatName(),
        constraint.getTable_db(),
        constraint.getTable_name(),
        constraint.getDc_name()
    );
  }

  public static String fullName(SQLCheckConstraint constraint) {
    return fullResourceName(
        constraint.getCatName(),
        constraint.getTable_db(),
        constraint.getTable_name(),
        constraint.getDc_name()
    );
  }

  private HiveNotificationEvent.Builder eventBuilder(String catalog, long diffId) {
    return HiveNotificationEvent.builder()
        .externalId(diffId)
        .eventType(HiveOperation.CREATE.toString())
        .catalogName(catalog)
        .messageFormat(messageFormat);
  }

  private String wrap(String rawMessage) {
    return hmsEntitySerializerWrapper.serialize(rawMessage);
  }
}
