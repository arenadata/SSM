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
package org.smartdata.hive.catalog;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.EnumUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.hive.metastore.TableType;
import org.apache.hadoop.hive.metastore.Warehouse;
import org.apache.hadoop.hive.metastore.api.Database;
import org.apache.hadoop.hive.metastore.api.MetaException;
import org.apache.hadoop.hive.metastore.api.Partition;
import org.apache.hadoop.hive.metastore.api.StorageDescriptor;
import org.apache.hadoop.hive.metastore.api.Table;
import org.apache.hadoop.hive.metastore.messaging.AddPartitionMessage;
import org.apache.hadoop.hive.metastore.messaging.AlterPartitionMessage;
import org.apache.hadoop.hive.metastore.messaging.AlterTableMessage;
import org.apache.hadoop.hive.metastore.messaging.DropPartitionMessage;
import org.apache.hadoop.hive.metastore.messaging.MessageDeserializer;
import org.apache.hadoop.hive.metastore.messaging.MessageFactory;
import org.smartdata.hive.fetch.HiveEntity;
import org.smartdata.hive.fetch.HiveNotificationEvent;
import org.smartdata.hive.fetch.HiveOperation;
import org.smartdata.hive.fetch.HmsEventStreamRecord;
import org.smartdata.hive.handler.HmsEventHandler;
import org.smartdata.retry.RetryException;
import org.smartdata.retry.RetrySupport;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

/**
 * Maintains the SSM copy of the source HMS catalog (databases, tables,
 * and their locations) based on the HMS events. Only tables with the physical
 * location and their partitions are stored, views are skipped.
 *
 * <p>All catalog updates are idempotent, so the handler can be fed
 * with raw HMS events in any fetching phase: snapshot, intermediate,
 * or in-flight events, without any additional events compaction.
 *
 * <p>Errors are propagated to the caller after retries,
 * which rolls back the HMS snapshot or stops the in-flight events fetching.
 * In order not to lose catalog updates, the handler should be executed <b>before</b>
 * the handler storing HMS events: in this case the event, which failed to be applied
 * to the catalog, isn't stored and is fetched again after the restart.
 *
 * <p>Each catalog update is executed in a separate nested transaction
 * so that it can be retried inside the outer HMS snapshot transaction.
 */
@Slf4j
public class CatalogHmsEventHandler implements HmsEventHandler {
  private final HiveCatalogDao catalogDao;
  private final RetrySupport retrySupport;
  private final Map<String, MessageDeserializer> deserializers;

  public CatalogHmsEventHandler(HiveCatalogDao catalogDao, RetrySupport retrySupport) {
    this.catalogDao = catalogDao;
    this.retrySupport = retrySupport;
    this.deserializers = new ConcurrentHashMap<>();
  }

  @Override
  public void handle(HmsEventStreamRecord record) throws Exception {
    if (!(record instanceof HiveNotificationEvent)) {
      return;
    }

    HiveNotificationEvent event = (HiveNotificationEvent) record;
    try {
      handleEvent(event);
    } catch (Exception e) {
      log.error("Error updating Hive catalog with HMS event {}", describe(event), e);
      throw e;
    }
  }

  private void handleEvent(HiveNotificationEvent event) throws Exception {
    HiveEntity entity = EnumUtils.getEnum(HiveEntity.class, event.getEntityType());
    HiveOperation operation = EnumUtils.getEnum(HiveOperation.class, event.getEventType());

    if (entity == null || operation == null) {
      log.warn("Error extracting entity or operation from event {}", describe(event));
      return;
    }

    switch (entity) {
      case DATABASE:
        executeDbUpdate(event, operation);
        return;
      case TABLE:
        executeTableUpdate(event, operation);
        return;
      case PARTITION:
        executePartitionUpdate(event, operation);
        return;
      default:
        log.debug("Skipping unsupported entity {} for event {}", entity, describe(event));
    }
  }

  private void executeDbUpdate(
      HiveNotificationEvent event, HiveOperation operation) throws Exception {
    switch (operation) {
      case CREATE:
        Database createdDb = deserializer(event)
            .getCreateDatabaseMessage(event.getMessage())
            .getDatabaseObject();
        withRetries(() -> catalogDao.upsertDatabase(toDatabaseInfo(createdDb)));
        return;
      case DROP:
        withRetries(() -> catalogDao.deleteDatabase(event.getDbName()));
        return;
      case ALTER:
        // Hive doesn't support databases renaming, so just replace the database state
        Database alteredDb = deserializer(event)
            .getAlterDatabaseMessage(event.getMessage())
            .getDbObjAfter();
        withRetries(() -> catalogDao.upsertDatabase(toDatabaseInfo(alteredDb)));
        return;
      default:
        log.debug("Skipping unknown db operation {} for event {}", operation, describe(event));
    }
  }

  private void executeTableUpdate(
      HiveNotificationEvent event, HiveOperation operation) throws Exception {
    switch (operation) {
      case CREATE:
        handleCreateTable(event);
        return;
      case DROP:
        handleDropTable(event);
        return;
      case ALTER:
        handleAlterTable(event);
        return;
      default:
        log.debug("Skipping unknown table operation {} for event {}", operation, describe(event));
    }
  }

  private void executePartitionUpdate(
      HiveNotificationEvent event, HiveOperation operation) throws Exception {
    switch (operation) {
      case CREATE:
        handleAddPartitions(event);
        return;
      case DROP:
        handleDropPartitions(event);
        return;
      case ALTER:
        handleAlterPartition(event);
        return;
      default:
        log.debug("Skipping unknown partition operation {} for event {}", operation, describe(event));
    }
  }

  private void handleCreateTable(HiveNotificationEvent event) throws Exception {
    Table createdTable = deserializer(event)
        .getCreateTableMessage(event.getMessage())
        .getTableObj();
    if (!isPhysicalTable(createdTable)) {
      log.debug("Skipping table creation without physical location for event {}", describe(event));
      return;
    }
    withRetries(() -> catalogDao.upsertTable(toTableInfo(createdTable)));
  }

  private void handleAlterTable(HiveNotificationEvent event) throws Exception {
    AlterTableMessage message = deserializer(event)
        .getAlterTableMessage(event.getMessage());
    Table tableBefore = message.getTableObjBefore();
    Table tableAfter = message.getTableObjAfter();

    // Hive doesn't allow changing the view to table and vice versa or to remove the table
    // location, so the table is supposed to be either physical or not before and after altering
    if (!isPhysicalTable(tableAfter)) {
      log.debug("Skipping table altering without physical location for event {}", describe(event));
      return;
    }

    withRetries(() -> catalogDao.alterTable(
        toTableInfo(tableBefore), toTableInfo(tableAfter)));
  }

  private void handleDropTable(HiveNotificationEvent event) throws Exception {
    Table droppedTable = deserializer(event)
        .getDropTableMessage(event.getMessage())
        .getTableObj();
    if (!isPhysicalTable(droppedTable)) {
      log.debug("Skipping table dropping without physical location for event {}", describe(event));
      return;
    }
    withRetries(() -> catalogDao.deleteTable(
        droppedTable.getDbName(), droppedTable.getTableName()));
  }

  private void handleAddPartitions(HiveNotificationEvent event) throws Exception {
    AddPartitionMessage message = deserializer(event)
        .getAddPartitionMessage(event.getMessage());
    Table table = message.getTableObj();
    if (!isPhysicalTable(table)) {
      log.debug("Skipping partitions adding for table without physical location for event {}",
          describe(event));
      return;
    }

    List<HivePartitionInfo> partitions = StreamSupport.stream(
            message.getPartitionObjs().spliterator(), false)
        .map(partition -> toPartitionInfo(table, partition))
        .filter(CatalogHmsEventHandler::hasLocation)
        .collect(Collectors.toList());

    if (partitions.isEmpty()) {
      log.debug("Skipping partitions adding without physical location for event {}", describe(event));
      return;
    }
    withRetries(() -> catalogDao.upsertPartitions(partitions));
  }

  private void handleAlterPartition(HiveNotificationEvent event) throws Exception {
    AlterPartitionMessage message = deserializer(event)
        .getAlterPartitionMessage(event.getMessage());
    Table table = message.getTableObj();
    if (!isPhysicalTable(table)) {
      log.debug("Skipping partition altering for table without physical location for event {}",
          describe(event));
      return;
    }

    HivePartitionInfo partitionBefore = toPartitionInfo(table, message.getPtnObjBefore());
    HivePartitionInfo partitionAfter = toPartitionInfo(table, message.getPtnObjAfter());
    // Hive doesn't allow removing the partition location, so the partition
    // is supposed to be either physical or not before and after altering
    if (!hasLocation(partitionAfter)) {
      log.debug("Skipping partition altering without physical location for event {}",
          describe(event));
      return;
    }

    // most of the partition alterations are statistics updates, which aren't stored
    if (partitionBefore.equals(partitionAfter)) {
      log.debug("Skipping partition altering without name or location change for event {}",
          describe(event));
      return;
    }

    withRetries(() -> catalogDao.alterPartition(partitionBefore, partitionAfter));
  }

  private void handleDropPartitions(HiveNotificationEvent event) throws Exception {
    DropPartitionMessage message = deserializer(event)
        .getDropPartitionMessage(event.getMessage());
    Table table = message.getTableObj();
    if (!isPhysicalTable(table)) {
      log.debug("Skipping partitions dropping for table without physical location for event {}",
          describe(event));
      return;
    }

    List<String> partitionNames = message.getPartitions()
        .stream()
        .map(partitionKeyValues -> partitionName(table, partitionKeyValues))
        .collect(Collectors.toList());

    withRetries(() -> catalogDao.deletePartitions(
        table.getDbName(), table.getTableName(), partitionNames));
  }

  private HiveDatabaseInfo toDatabaseInfo(Database database) {
    return HiveDatabaseInfo.builder()
        .name(database.getName())
        .catalogName(database.getCatalogName())
        .location(database.getLocationUri())
        .build();
  }

  private HiveTableInfo toTableInfo(Table table) {
    return HiveTableInfo.builder()
        .dbName(table.getDbName())
        .name(table.getTableName())
        .catalogName(table.getCatName())
        .location(location(table))
        .build();
  }

  private HivePartitionInfo toPartitionInfo(Table table, Partition partition) {
    try {
      String location = Optional.ofNullable(partition.getSd())
          .map(StorageDescriptor::getLocation)
          .orElse(null);

      return HivePartitionInfo.builder()
          .dbName(table.getDbName())
          .tableName(table.getTableName())
          .name(Warehouse.makePartName(table.getPartitionKeys(), partition.getValues()))
          .location(location)
          .build();
    } catch (MetaException e) {
      throw new RuntimeException(e);
    }
  }

  private static String partitionName(
      Table table, Map<String, String> partitionKeyValues) {
    List<String> values = table.getPartitionKeys()
        .stream()
        .map(key -> partitionKeyValues.get(key.getName()))
        .collect(Collectors.toList());
    try {
      return Warehouse.makePartName(table.getPartitionKeys(), values);
    } catch (MetaException e) {
      throw new RuntimeException(e);
    }
  }

  private static boolean hasLocation(HivePartitionInfo partition) {
    return StringUtils.isNotBlank(partition.getLocation());
  }

  private static boolean isPhysicalTable(Table table) {
    return !TableType.VIRTUAL_VIEW.name().equals(table.getTableType())
        && StringUtils.isNotBlank(location(table));
  }

  private static String location(Table table) {
    return Optional.ofNullable(table.getSd())
        .map(StorageDescriptor::getLocation)
        .orElse(null);
  }

  private void withRetries(Runnable action) throws RetryException {
    retrySupport.withRetries(() ->
        catalogDao.executeWithoutResult(status -> action.run()));
  }

  private MessageDeserializer deserializer(HiveNotificationEvent event) {
    return Optional.ofNullable(event.getMessageFormat())
        .map(format -> deserializers.computeIfAbsent(format, this::createDeserializer))
        .orElseThrow(() -> new IllegalArgumentException("HMS event message format is not specified"));
  }

  private MessageDeserializer createDeserializer(String messageFormat) {
    try {
      return MessageFactory.getInstance(messageFormat).getDeserializer();
    } catch (Exception e) {
      throw new IllegalArgumentException("Unsupported HMS event message format: " + messageFormat, e);
    }
  }

  private static String describe(HiveNotificationEvent event) {
    return String.format("{id=%d, externalId=%d, type=%s, entityType=%s, name=%s}",
        event.getId(), event.getExternalId(), event.getEventType(),
        event.getEntityType(), event.getFullName());
  }
}
